using System;
using SWSniff.Core.Packets;

namespace SWSniff.Core
{
    public class SnifferEventArgs : EventArgs
    {
        public int SocketId { get; }
        public SWPacket Packet { get; }
        public bool Outgoing { get; }

        public SnifferEventArgs(SWPacket packet, bool outgoing, int socketId)
        {
            SocketId = socketId;
            Packet = packet;
            Outgoing = outgoing;
        }
    }
}
