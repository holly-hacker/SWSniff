using System;
using System.Diagnostics;
using System.Text;

namespace SWSniff.SoulWorker.Packets
{
    public class PacketSystemKeepAlive : SWPacket
    {
        public int Ticks, Unknown2, Unknown3;
        public string Checksum;

        protected override void Deserialize(byte[] data)
        {
            Debug.Assert(ID == 0x0105);

            if (data.Length == 0x2E) {
                Ticks = BitConverter.ToInt32(data, 0);
                Unknown2 = BitConverter.ToInt32(data, 4);
                Unknown3 = BitConverter.ToInt32(data, 8);
                short len = BitConverter.ToInt16(data, 12);
                Debug.Assert(len == 0x20, "Unexpected checksum length");
                Checksum = Encoding.ASCII.GetString(data, 14, len);
            }
            else Debug.Fail("Unexpected packet length");
        }

        public override string ToString() => $"KeepAlive, TimeSinceSystemStart={new TimeSpan(0, 0, 0, 0, Ticks)}, always_zero={Unknown2}, bla={Unknown3}, checksum={Checksum}";
    }
}
