using System;
using SWSniff.Core.Packets;

namespace SWSniff.Core
{
    public class SnifferEventArgs : EventArgs
    {
        public SWPacket Packet { get; }
        public bool Outgoing { get; }

        public SnifferEventArgs(SWPacket packet, bool outgoing)
        {
            Packet = packet;
            Outgoing = outgoing;
        }
    }
}
