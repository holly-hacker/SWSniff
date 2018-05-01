using System;
using System.Runtime.InteropServices;

namespace SWSniff.Internal.Hooking
{
    internal class Hook
    {
        IntPtr hProc;
        IntPtr hOrig;

        public Hook(string module, string function)
        {
            // Find the handle to the original function and store it
            hProc = Native.GetModuleHandle(null);
            hOrig = Native.GetProcAddress(Native.GetModuleHandle(module), function);
        }

        public void Apply(Delegate d)
        {
            // Get delegate ptr
            var ptr = Marshal.GetFunctionPointerForDelegate(d);

            // Pin the delegate
            var h = GCHandle.FromIntPtr(ptr);   // TODO: not sure if needed

            AITWinAPI.PleaseSendHelp(hProc, "x", IntPtr.Zero);
        }

        //public Hook(IntPtr src, IntPtr dst) { }
        //public Hook(IntPtr src, Delegate dest) : this(src, Marshal.GetFunctionPointerForDelegate(dest)) { }
    }
}
