using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
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

        public Sniffer()
        {
            if (!File.Exists(Constants.FilenameWspe))
                new WebClient().DownloadFile(Constants.UrlWspe, Constants.FilenameWspe);
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
            byte[] bufferMsgHdr = new byte[14];
            byte[] bufferData = new byte[0];
            //read header
            while (_pipeIn.Read(bufferMsgHdr, 0, 14) != 0) {
                var h = (PipeMessageHeader)RandomHelper.DeSerializeObj(bufferMsgHdr, typeof(PipeMessageHeader));

                //if there's data
                if (h.DataSize != 0) {
                    bufferData = new byte[h.DataSize];
                    _pipeIn.Read(bufferData, 0, bufferData.Length);
                }
                
                switch (h.Command)
                {
                    case PipeCommand.Init when h.Function == PipeFunction.InitDecrypt:
                        if (h.Extra == 0)
                            throw new Exception("Invalid license.");

                        //enable monitoring
                        _pipeOut.Write(RandomHelper.SerializeObj(new PipeMessageHeader(PipeCommand.EnableMonitor)), 0, Marshal.SizeOf(typeof(PipeMessageHeader)));
                        break;
                    case PipeCommand.Data when h.DataSize > 0:
                        //Console.WriteLine($"{h.Function} ({h.Extra}): {string.Join("-", bufferData.Select(x => x.ToString("X2")))}");
                        switch (h.Function) {
                            case PipeFunction.FuncSend:
                            case PipeFunction.FuncSendTo:
                            case PipeFunction.FuncWsaSend:
                            case PipeFunction.FuncWsaSendTo:
                            case PipeFunction.FuncWsaSendDisconnect:
                                HandlePacket(bufferData, true);
                                break;
                            case PipeFunction.FuncRecv:
                            case PipeFunction.FuncRecvFrom:
                            case PipeFunction.FuncWsaRecv:
                            case PipeFunction.FuncWsaRecvFrom:
                            case PipeFunction.FuncWsaRecvDisconnect:
                                HandlePacket(bufferData, false);
                                break;
                        }
                        break;

                    default:
                        Console.WriteLine($"Unhandled packet: cmd={h.Command}, fun={h.Function}, ext={h.Extra}, datalen={h.DataSize}");
                        if (h.DataSize != 0)
                            Console.WriteLine(string.Join("-", bufferData.Select(x => x.ToString("X2"))));
                        break;
                }
            }
        }

        private static void HandlePacket(byte[] data, bool outgoing)
        {
            SWPacket p = SWPacket.Parse(data);

            Console.WriteLine($"{(outgoing ? "[OUT]" : "[IN] ")} {p.ID0:X2} {p.ID1:X2} {p.ID2:X2} (len={p.Data.Length})");
        }
    }
}
