using System;
using System.Diagnostics;

namespace SWSniff.Core.Packets.SW
{
    public class PacketShopSell : SWPacket
    {
        public int VendorID;
        public short InvPos;
        public byte Unknown0, Unknown1, Unknown2;   //0, 1 and 2 respectively

        protected override void Deserialize(byte[] data)
        {
            Debug.Assert(ID == 0x0902);

            if (data.Length == 9) {
                VendorID = BitConverter.ToInt32(data, 0);
                Unknown0 = data[4];
                Unknown1 = data[5];
                Unknown2 = data[6];
                InvPos = BitConverter.ToInt16(data, 7);
            }
            else Debug.Fail("Unexpected packet length");
        }

        public override string ToString() => $"Sold inventory pos {InvPos} to vendor {VendorID:X8}";
    }
}
