using System;
using System.Diagnostics;

namespace SWSniff.Core.Packets.SW
{
    internal class PacketShopBuy : SWPacket
    {
        public int VendorID, ItemID;
        public short Count;
        public byte Unknown1;   //0, flags perhaps?

        protected override void Deserialize(byte[] data)
        {
            Debug.Assert(ID == 0x0901);

            if (data.Length == 11) {
                VendorID = BitConverter.ToInt32(data, 0);
                ItemID = BitConverter.ToInt32(data, 4);
                Count = BitConverter.ToInt16(data, 8);
                Unknown1 = data[10];
            } else Debug.Fail("Unexpected packet length");
        }

        public override string ToString() => $"Bought item {ItemID:X} x{Count} from vendor {VendorID:X8}";
    }
}
