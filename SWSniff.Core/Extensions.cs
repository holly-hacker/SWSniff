using System;
using SWSniff.Core.Packets;

namespace SWSniff.Core
{
    public static class Extensions
    {
        public static PacketType PacketType(this SWPacket p) => (PacketType)p.ID;
        public static string IDString(this SWPacket p) => Enum.GetName(typeof(PacketType), (PacketType)p.ID) ?? p.ID.ToString("X4");
    }
}
