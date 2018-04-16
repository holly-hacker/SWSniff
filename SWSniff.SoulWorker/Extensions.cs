using System;
using SWSniff.SoulWorker.Packets;

namespace SWSniff.SoulWorker
{
    public static class Extensions
    {
        public static PacketType PacketType(this SWPacket p) => (PacketType)p.ID;
        public static byte ID1(this PacketType p) => (byte)((short)p >> 8);
        public static byte ID2(this PacketType p) => (byte)p;
        public static string IDString(this SWPacket p) => Enum.GetName(typeof(PacketType), (PacketType)p.ID) ?? p.ID.ToString("X4");
    }
}
