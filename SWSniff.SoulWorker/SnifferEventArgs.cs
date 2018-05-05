using System;
using SWSniff.SoulWorker.Packets;

namespace SWSniff.SoulWorker
{
    public class SnifferEventArgs : EventArgs
    {
        public uint SocketId { get; }
        public SWPacket Packet { get; }
        public bool Outgoing { get; }

        public SnifferEventArgs(SWPacket packet, bool outgoing, uint socketId)
        {
            SocketId = socketId;
            Packet = packet;
            Outgoing = outgoing;
        }
    }
}
