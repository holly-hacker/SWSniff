using System;
using System.Diagnostics;
using System.IO;
using SWSniff.Core.Interfaces;

namespace SWSniff.SoulWorker.Packets
{
    public class PacketItemJoinStack : SWPacket, ICanSerialize
    {
        public byte InvIDSrc, InvIDDst;
        public int Unknown1, Unknown2;
        public short InvPosSrc, InvPosDst;
        public short Count;

        protected override void Deserialize(byte[] data)
        {
            Debug.Assert(ID == 0x0803);

            if (data.Length == 16) {
                InvIDSrc = data[0];
                Unknown1 = BitConverter.ToInt32(data, 1);
                InvPosSrc = BitConverter.ToInt16(data, 5);
                InvIDDst = data[7];
                Unknown2 = BitConverter.ToInt32(data, 8);
                InvPosDst = BitConverter.ToInt16(data, 12);
                Count = BitConverter.ToInt16(data, 14);
            }
            else Debug.Fail("Unexpected packet length");
        }

        public byte[] Serialize()
        {
            using (var ms = new MemoryStream(16))
            using (var bw = new BinaryWriter(ms)) {
                bw.Write(InvIDSrc);
                bw.Write(Unknown1);
                bw.Write(InvPosSrc);
                bw.Write(InvIDDst);
                bw.Write(Unknown2);
                bw.Write(InvPosDst);
                bw.Write(Count);
                return ms.ToArray();
            }
        }

        public override string ToString() => $"Added {Count} items to stack at pos {InvPosSrc}->{InvPosDst}, inv {InvIDSrc}->{InvIDDst}, unk {Unknown1}->{Unknown2}";
    }
}
