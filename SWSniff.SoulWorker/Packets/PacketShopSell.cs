using System;
using System.Diagnostics;
using System.IO;
using SWSniff.Core.Interfaces;

namespace SWSniff.SoulWorker.Packets
{
    public class PacketShopSell : SWPacket, ICanSerialize
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

        public byte[] Serialize()
        {
            using (var ms = new MemoryStream(9))
            using (var bw = new BinaryWriter(ms)) {
                bw.Write(VendorID);
                bw.Write(Unknown0);
                bw.Write(Unknown1);
                bw.Write(Unknown2);
                bw.Write(InvPos);

                return ms.ToArray();
            }
        }

        public override string ToString() => $"Sold inventory pos {InvPos} to vendor {VendorID:X8} ({Unknown0} {Unknown1} {Unknown2})";
    }
}
