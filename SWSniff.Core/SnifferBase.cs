using System;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Threading;
using SWSniff.Internal;
using SWSniff.Internal.Interop;

namespace SWSniff.Core
{
    public abstract class SnifferBase
    {
        private static readonly Encoding EncA = Encoding.GetEncoding(0x6FAF);
        private readonly string _procName;
        private readonly NamedPipeServerStream _server;
        private Thread _pipeThread;

        protected SnifferBase(string procName)
        {
            _procName = procName;
            _server = new NamedPipeServerStream(Internal.Constants.PipeNameIn);

            // Check for required DLL's
            if (!File.Exists(Constants.FilenameBootstrapDLL))
                throw new Exception("Bootstrap DLL not found, make sure it is built.");
            if (!File.Exists(Constants.FilenameInternalDLL))
                throw new Exception("Internal DLL not found");
        }

        public void WaitForProcess(int sleepMs = 100)
        {
            while (GeneralHelper.GetProcessID(_procName) == null)
                Thread.Sleep(sleepMs);
        }

        public void Start()
        {
            // Find process
            int pid = GeneralHelper.GetProcessID(_procName) ?? throw new Exception("proc not found");
            
            // Open process
            IntPtr hProc = Native.OpenProcess(Native.ProcessAccessFlags.All, false, pid);
            if (hProc == IntPtr.Zero)
                throw new Exception("Cannot open process.");

            // Write LoadLibraryA parameter to other process
            byte[] filenameBytes = EncA.GetBytes(Path.Combine(Directory.GetCurrentDirectory(), Constants.FilenameBootstrapDLL));
            IntPtr ptrMem = Native.VirtualAllocEx(hProc, (IntPtr)0, (uint)filenameBytes.Length, Native.AllocationType.COMMIT, Native.MemoryProtection.EXECUTE_READ);
            if (ptrMem == IntPtr.Zero)
                throw new Exception("Cannot allocate process memory.");
            if (!Native.WriteProcessMemory(hProc, ptrMem, filenameBytes, (uint)filenameBytes.Length, out _))
                throw new Exception("Cannot write to process memory.");

            // Call LoadLibraryA
            IntPtr ptrLoadLib = Native.GetProcAddress(Native.GetModuleHandle("KERNEL32.DLL"), "LoadLibraryA");
            Native.CreateRemoteThread(hProc, IntPtr.Zero, 0, ptrLoadLib, ptrMem, 0, IntPtr.Zero);

            // Wait for injected lib to ping back
            _server.WaitForConnection();

            // Start reading from pipe
            _pipeThread = new Thread(PipeRead);
            _pipeThread.Start();
        }

        public void Inject(byte[] data, uint sockId)
        {
            throw new NotImplementedException();
        }

        private void PipeRead()
        {
            while (PacketHeader.ReadFromPipe(_server, out PacketHeader pkg)) {
                byte[] data = null;

                if (pkg.Length > 0) {
                    data = new byte[(int)pkg.Length];
                    _server.Read(data, 0, (int)pkg.Length);
                }

                switch (pkg.Command) {
                    case PacketCommand.ReadonlyPacketInfo:
                        HandlePacket(pkg.SocketId, data, pkg.Function.HasFlag(PacketFunction.Send));
                        break;
                    default:
                    case PacketCommand.None:
                        throw new ArgumentOutOfRangeException();
                }
            }
        }

        protected abstract void HandlePacket(uint socketId, byte[] msg, bool outgoing);
    }
}
