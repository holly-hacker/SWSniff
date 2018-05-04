using System;
using System.IO;
using System.Text;
using System.Threading;

namespace SWSniff.Core
{
    public abstract class SnifferBase
    {
        private static readonly Encoding EncA = Encoding.GetEncoding(0x6FAF);
        private readonly string _procName;

        protected SnifferBase(string procName)
        {
            _procName = procName;

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

            // Start pipes
            // TODO

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
            // TODO
            
            // Start reading from pipe
            // TODO
        }

        public void Inject(byte[] data, int sockId)
        {
            throw new NotImplementedException();
        }

        protected abstract void HandlePacket(object msg, bool outgoing);
    }
}
