using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using SWSniff.Core.Interop;
using SWSniff.Core.Packets;

namespace SWSniff.Core
{
    public class Sniffer
    {
        private static readonly Encoding EncA = Encoding.GetEncoding(0x6FAF);
        private NamedPipeClientStream _pipeOut;
        private NamedPipeServerStream _pipeIn;
        private Thread _pipeThread;

        public event PacketEventDelegate PacketAction;

        public delegate void PacketEventDelegate(object sender, SnifferEventArgs e);

        public Sniffer()
        {
            if (!File.Exists(Constants.FilenameWspe))
                new WebClient().DownloadFile(Constants.UrlWspe, Constants.FilenameWspe);
        }

        public void WaitForProcess(int sleepMs = 100)
        {
            while (GeneralHelper.GetProcessID() == null)
                Thread.Sleep(sleepMs);
        }

        public void Start()
        {
            //find process
            int pid = GeneralHelper.GetProcessID() ?? throw new Exception("proc not found");

            //start pipes
            try {
                _pipeOut = new NamedPipeClientStream(".", "wspe.send." + pid.ToString("X8"), PipeDirection.Out, PipeOptions.Asynchronous);
                _pipeIn = new NamedPipeServerStream("wspe.recv." + pid.ToString("X8"), PipeDirection.In, 1, PipeTransmissionMode.Message);
            } catch (Exception ex) {
                throw new Exception("Cannot attach to process!", ex);
            }

            //open process
            IntPtr hProc = Native.OpenProcess(Native.ProcessAccessFlags.All, false, pid);
            if (hProc == IntPtr.Zero)
                throw new Exception("Cannot open process.");

            //write LoadLibraryA parameter to other process
            byte[] filenameBytes = EncA.GetBytes(Path.Combine(Directory.GetCurrentDirectory(), Constants.FilenameWspe));
            IntPtr ptrMem = Native.VirtualAllocEx(hProc, (IntPtr)0, (uint)filenameBytes.Length, Native.AllocationType.COMMIT, Native.MemoryProtection.EXECUTE_READ);
            if (ptrMem == IntPtr.Zero)
                throw new Exception("Cannot allocate process memory.");
            if (!Native.WriteProcessMemory(hProc, ptrMem, filenameBytes, (uint)filenameBytes.Length, out _))
                throw new Exception("Cannot write to process memory.");

            //call LoadLibraryA
            IntPtr ptrLoadLib = Native.GetProcAddress(Native.GetModuleHandle("KERNEL32.DLL"), "LoadLibraryA");
            Native.CreateRemoteThread(hProc, IntPtr.Zero, 0, ptrLoadLib, ptrMem, 0, IntPtr.Zero);

            //wait for injected lib to ping back
            _pipeIn.WaitForConnection();
            _pipeOut.Connect();
            
            //register
            _pipeOut.Write(BitConverter.GetBytes(Constants.RegName.Length), 0, 1);
            _pipeOut.Write(EncA.GetBytes(Constants.RegName), 0, Constants.RegName.Length);
            _pipeOut.Write(EncA.GetBytes(Constants.RegKey), 0, Constants.RegKey.Length);

            //start reading from pipe
            _pipeThread = new Thread(PipeRead) {IsBackground = true};
            _pipeThread.Start();
        }

        public void Inject(PacketType t, ICanSerialize p, int sockId)
        {
            //serialize the packet
            byte[] dataPacket = p.Serialize();
            Inject(t, dataPacket, sockId);
        }

        public void Inject(PacketType t, byte[] dataPacket, int sockId)
        {
            short len = (short)(dataPacket.Length+7);

            //get buffer to copy in the final byte array
            byte[] buffer = new byte[len];

            buffer[0] = 2;
            buffer[1] = 0;
            buffer[2] = (byte)(len >> 0);
            buffer[3] = (byte)(len >> 8);
            buffer[4] = 1;
            buffer[5] = t.ID1();
            buffer[6] = t.ID2();

            //fill in the data
            Array.Copy(dataPacket, 0, buffer, 7, dataPacket.Length);

            GeneralHelper.XorPacket(buffer);

            Inject(buffer, sockId);
        }

        public void Inject(byte[] data, int sockId)
        {
            new PipeMessage(PipeCommand.Inject, PipeFunction.FuncSend, sockId, data).Send(_pipeOut);
        }

        private void PipeRead()
        {
            while (PipeMessage.ReadFromPipe(_pipeIn, out PipeMessage p)) {
                
                switch (p.Header.Command)
                {
                    case PipeCommand.Init when p.Header.Function == PipeFunction.InitDecrypt:
                        if (p.Header.Extra == 0)
                            throw new Exception("Invalid license.");

                        //enable monitoring
                        new PipeMessage(PipeCommand.EnableMonitor).Send(_pipeOut);
                        break;
                    case PipeCommand.Data when p.Header.DataSize >= 3 && BitConverter.ToUInt16(p.Data, 0) == 2:
                        switch (p.Header.Function) {
                            case PipeFunction.FuncSend:
                            case PipeFunction.FuncSendTo:
                            case PipeFunction.FuncWsaSend:
                            case PipeFunction.FuncWsaSendTo:
                            case PipeFunction.FuncWsaSendDisconnect:
                                HandlePacket(p, true);
                                break;
                            case PipeFunction.FuncRecv:
                            case PipeFunction.FuncRecvFrom:
                            case PipeFunction.FuncWsaRecv:
                            case PipeFunction.FuncWsaRecvFrom:
                            case PipeFunction.FuncWsaRecvDisconnect:
                                HandlePacket(p, false);
                                break;
                        }
                        break;

                    default:
                        Debug.WriteLine($"Unhandled packet: cmd={p.Header.Command}, fun={p.Header.Function}, ext={p.Header.Extra}, datalen={p.Header.DataSize}");

                        //if possible data packet, print contents
                        if (p.Header.DataSize >= 7 && BitConverter.ToUInt16(p.Data, 2) == p.Header.DataSize)
                            Debug.WriteLine(string.Join("-", p.Data.Select(x => x.ToString("X2"))));
                        break;
                }
            }
        }

        /// <summary> Reads all packets from the message and invokes the event handlers. </summary>
        private void HandlePacket(PipeMessage msg, bool outgoing)
        {
            Debug.Assert(msg.HasData);
            var data = msg.Data;
            
            int packetStart = 0;
            while (packetStart < data.Length) {
                //read cleartext packet header
                Debug.Assert(BitConverter.ToInt16(data, packetStart + 0) == 0x0002, "Unknown xor offset");
                short packetLen = BitConverter.ToInt16(data, packetStart + 2);

                //extract packet and parse it
                byte[] slice = new byte[packetLen]; //TODO: C# 7 slicing
                Array.Copy(data, packetStart, slice, 0, packetLen);
                SWPacket p = SWPacket.Parse(slice);
                PacketAction?.Invoke(this, new SnifferEventArgs(p, outgoing, msg.Header.SocketId));

                //update packet start
                packetStart += packetLen;
            }
        }
    }
}
