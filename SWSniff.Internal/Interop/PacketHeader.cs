using System;
using System.IO.Pipes;
using System.Runtime.InteropServices;

namespace SWSniff.Internal.Interop
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct PacketHeader
    {
        public const int PacketLength = sizeof(PacketCommand) + sizeof(PacketFunction) + sizeof(uint) + sizeof(uint);

        public PacketCommand Command;
        public PacketFunction Function;
        public uint SocketId;
        public uint Length;

        public static bool ReadFromPipe(NamedPipeServerStream pipe, out PacketHeader msg)
        {
            msg = new PacketHeader();
            byte[] bufferMsgHdr = new byte[PacketLength];

            // Read the packet header from the pipe (blocking)
            if (pipe.Read(bufferMsgHdr, 0, PacketLength) != 0)
            {
                // Convert byte array to struct
                GCHandle handle = GCHandle.Alloc(bufferMsgHdr, GCHandleType.Pinned);
                IntPtr ptr = handle.AddrOfPinnedObject();
                msg = Marshal.PtrToStructure<PacketHeader>(ptr);
                handle.Free();
                
                return true;
            }
            else return false;
        }
    }
}
