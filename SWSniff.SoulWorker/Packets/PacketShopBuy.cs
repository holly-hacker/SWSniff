using System;
using System.Diagnostics;
using System.IO;
using SWSniff.Core.Interfaces;

namespace SWSniff.SoulWorker.Packets
{
    public class PacketShopBuy : SWPacket, ICanSerialize
    {
        public int VendorID, ItemID;
        public short Count;
        public byte Unknown1;   //0, flags perhaps?

        public PacketShopBuy() { }

        public PacketShopBuy(int vid, int item, short count, byte unk1)
        {
            VendorID = vid;
            ItemID = item;
            Count = count;
            Unknown1 = unk1;
        }

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

        public byte[] Serialize()
        {
            using (var ms = new MemoryStream(11))
            using (var bw = new BinaryWriter(ms)) {
                bw.Write(VendorID);
                bw.Write(ItemID);
                bw.Write(Count);
                bw.Write(Unknown1);

                return ms.ToArray();
            }
        }

        public override string ToString() => $"Bought item {ItemID:X} x{Count} from vendor {VendorID:X8} (idk={Unknown1})";
    }
}
