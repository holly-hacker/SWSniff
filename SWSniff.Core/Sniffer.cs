using System;
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
            while (RandomHelper.GetProcessID() == null)
                Thread.Sleep(sleepMs);
        }

        public void Start()
        {
            //find process
            int pid = RandomHelper.GetProcessID() ?? throw new Exception("proc not found");

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
                                HandlePacket(p.Data, true);
                                break;
                            case PipeFunction.FuncRecv:
                            case PipeFunction.FuncRecvFrom:
                            case PipeFunction.FuncWsaRecv:
                            case PipeFunction.FuncWsaRecvFrom:
                            case PipeFunction.FuncWsaRecvDisconnect:
                                HandlePacket(p.Data, false);
                                break;
                        }
                        break;

                    default:
                        Console.WriteLine($"Unhandled packet: cmd={p.Header.Command}, fun={p.Header.Function}, ext={p.Header.Extra}, datalen={p.Header.DataSize}");

                        //if possible data packet, print contents
                        if (p.Header.DataSize >= 7 && BitConverter.ToUInt16(p.Data, 2) == p.Header.DataSize)
                            Console.WriteLine(string.Join("-", p.Data.Select(x => x.ToString("X2"))));
                        break;
                }
            }
        }

        private void HandlePacket(byte[] data, bool outgoing)
        {
            SWPacket p = SWPacket.Parse(data);

            PacketAction?.Invoke(this, new SnifferEventArgs(p, outgoing));
        }
    }
}
