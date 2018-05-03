using System;
using System.Runtime.InteropServices;

namespace SWSniff.Internal.Hooking
{
    internal class HookWrapper<TDelegate>
    {
        public TDelegate OriginalFunction { get; }

        private readonly IntPtr _hProc;
        private readonly IntPtr _hOrig;
        private readonly string _function;

        public HookWrapper(string module, string function)
        {
            _function = function;

            // Find the handle to the original function and store it
            _hProc = Native.GetModuleHandle(null);
            _hOrig = Native.GetProcAddress(Native.GetModuleHandle(module), function);

            // Store the original function in a delegate
            OriginalFunction = Marshal.GetDelegateForFunctionPointer<TDelegate>(_hOrig);
        }

        public void Apply(TDelegate d)
        {
            // Get delegate ptr
            var ptr = Marshal.GetFunctionPointerForDelegate(d);

            Console.WriteLine("Applying IAT Hook");
            IATHook.Apply(_hProc, _function, ptr);
        }
    }
}
