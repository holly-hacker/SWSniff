using System;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace SWSniff.Internal.Hooking
{
    internal static unsafe class IATHook
    {
        public static bool Apply(IntPtr modHandle, string name, IntPtr delegatePtr)
        {
            int x = 0;
            const ushort IMAGE_DIRECTORY_ENTRY_IMPORT = 0x1;
            var imports = (ImageImportDescriptor*)Native.ImageDirectoryEntryToDataEx(modHandle, true, IMAGE_DIRECTORY_ENTRY_IMPORT, ref x, IntPtr.Zero);
            ImageImportDescriptor deref;
            do {
                deref = *imports;

                uint j = 0;

                uint oThunk = *(uint*)((byte*)modHandle + deref.OriginalFirstThunk);
                uint fThunk = *(uint*)((byte*)modHandle + deref.FirstThunk);

                while (oThunk != 0) {
                    string s = Marshal.PtrToStringAnsi(new IntPtr((byte*)modHandle + oThunk + 0x2));

                    if (s == name) {
                        // Make memory writable
                        byte* funcAddr = (byte*)fThunk;
                        Native.VirtualProtect(new IntPtr((int)funcAddr), 4, Native.MemoryProtection.EXECUTE_READWRITE, out var old);

                        // Write delegate pointer
                        *(uint*)funcAddr = (uint)delegatePtr.ToInt32();

                        // Reset memory permissions
                        Native.VirtualProtect(new IntPtr((int)funcAddr), 4, old, out _);

                        // Log some values to the console for debugging purposes
                        Console.WriteLine($"IAT hooked function '{s}', changed address {(uint)funcAddr:X8} to {*(uint*)funcAddr:X8} (at thunk base offset {(uint)deref.FirstThunk:X8})");
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
