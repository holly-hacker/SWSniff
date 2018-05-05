using System;

namespace SWSniff.Internal
{
    [Flags]
    public enum PacketFunction : byte
    {
        None = 0,
        Send = 0b0000_0001,
        Recv = 0b0000_0010,
        WSA  = 0b0000_0100,
        WSASend = WSA + Send,
        WSARecv = WSA + Recv,
    }

    public enum PacketCommand : byte
    {
        None = 0,
        ReadonlyPacketInfo = 1,
    }
}
