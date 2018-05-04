using System;
using System.Runtime.InteropServices;

namespace SWSniff.Internal.Hooking
{
    internal static unsafe class IATHook
    {
        public static bool Apply(IntPtr modHandle, string name, IntPtr delegatePtr) => Apply(modHandle, name, 0, delegatePtr, false);
        public static bool Apply(IntPtr modHandle, string name, int oid, IntPtr delegatePtr, bool ordinal = true)
        {
            int x = 0;
            const ushort IMAGE_DIRECTORY_ENTRY_IMPORT = 0x1;
            var imports = (ImageImportDescriptor*)Native.ImageDirectoryEntryToDataEx(modHandle, true, IMAGE_DIRECTORY_ENTRY_IMPORT, ref x, IntPtr.Zero);
            ImageImportDescriptor deref;
            do {
                deref = *imports;

                // We can get the name of this module
                string modName = Marshal.PtrToStringAnsi(new IntPtr((byte*)modHandle + deref.Name));

                uint j = 0;

                uint oThunk = *(uint*)((byte*)modHandle + deref.OriginalFirstThunk);
                uint fThunk = *(uint*)((byte*)modHandle + deref.FirstThunk);

                while (oThunk != 0) {
                    bool match = false;

                    // Get the pointer to the function name
                    byte* nModFuncName = (byte*)modHandle + oThunk + 0x2;

                    if (ordinal && ((int)nModFuncName & 0x80000000) != 0) {
                        // If the top bit is set, there is no name                        
                        //Console.WriteLine($"{modName}: {(int)fThunk:X8} - function {oThunk & ~0x80000000}");

                        // So instead, check if the ordinal ID matches ours.
                        if ((oThunk & ~0x80000000) == oid)
                            match = true;
                    }
                    else if (!ordinal) {
                        // If the top bit isn't set, check this name against the desired one
                        string s = Marshal.PtrToStringAnsi(new IntPtr(nModFuncName));
                        //Console.WriteLine($"{modName}: {(int)fThunk:X8}/{(int)((byte*)modHandle + oThunk):X8} - {s}");

                        if (s == name)
                            match = true;
                    }

                    if (match) {
                        // Make memory writable (funcAddr is a pointer to the function pointer)
                        byte* funcAddr = (byte*)((uint*)((byte*)modHandle + deref.FirstThunk) + j);
                        Native.VirtualProtect(new IntPtr((int)funcAddr), 4, Native.MemoryProtection.EXECUTE_READWRITE, out var old);

                        // Write delegate pointer
                        *(uint*)funcAddr = (uint)delegatePtr.ToInt32();

                        // Reset memory permissions
                        Native.VirtualProtect(new IntPtr((int)funcAddr), 4, old, out _);

                        // Log some values to the console for debugging purposes
                        Console.WriteLine($"IAT hooked function '{name}', changed pointer from 0x{fThunk:X8} to 0x{*(uint*)funcAddr:X8}");
                        return true;
                    }

                    j++;

                    oThunk = *((uint*)((byte*)modHandle + deref.OriginalFirstThunk) + j);
                    fThunk = *((uint*)((byte*)modHandle + deref.FirstThunk) + j);
                }
                imports++;
            } while (deref.Characteristics != 0);

            return false;
        }

        [StructLayout(LayoutKind.Explicit)]
        private struct ImageImportDescriptor
        {
            [FieldOffset(0x0)] public uint Characteristics;
            [FieldOffset(0x0)] public uint OriginalFirstThunk;
            [FieldOffset(0x4)] public uint TimeDateStamp;
            [FieldOffset(0x8)] public uint ForwarderChain; /* -1 if no forwarders */
            [FieldOffset(0xC)] public uint Name;

            // RVA to IAT (if bound this IAT has actual addresses)
            [FieldOffset(0x10)] public uint FirstThunk;    //ptr
        }
    }
}
