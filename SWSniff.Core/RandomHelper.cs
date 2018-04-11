using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;

namespace SWSniff.Core
{
    internal static class RandomHelper
    {
        public static ushort? GetProcessID() => (ushort?)Process.GetProcessesByName(Constants.ProcName).FirstOrDefault()?.Id;

        public static byte[] SerializeObj(object obj)
        {
            int size = Marshal.SizeOf(obj);
            byte[] buffer = new byte[size];

            GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            IntPtr ptr = handle.AddrOfPinnedObject();
            Marshal.StructureToPtr(obj, ptr, false);
            handle.Free();
            return buffer;
        }

        public static object DeSerializeObj(byte[] data, Type t)
        {
            int size = Marshal.SizeOf(t);
            if (size > data.Length)
                return null;

            GCHandle handle = GCHandle.Alloc(data, GCHandleType.Pinned);
            IntPtr ptr = handle.AddrOfPinnedObject();
            object obj = Marshal.PtrToStructure(ptr, t);
            handle.Free();
            return obj;
        }
    }
}
