using System;
using System.Diagnostics;
using System.IO;
using SWSniff.Core.Interfaces;

namespace SWSniff.SoulWorker.Packets
{
    public class PacketItemSplitStack : SWPacket, ICanSerialize
    {
        public byte InvIDSrc, InvIDDst;
        public int Unknown1;
        public short InvPosSrc, InvPosDst;
        public short Count;

        protected override void Deserialize(byte[] data)
        {
            Debug.Assert(ID == 0x0804);

            if (data.Length == 12) {
                InvIDSrc = data[0];
                Unknown1 = BitConverter.ToInt32(data, 1);
                InvPosSrc = BitConverter.ToInt16(data, 5);
                InvIDDst = data[7];
                InvPosDst = BitConverter.ToInt16(data, 8);
                Count = BitConverter.ToInt16(data, 10);
            }
            else Debug.Fail("Unexpected packet length");
        }

        public byte[] Serialize()
        {
            using (var ms = new MemoryStream(12))
            using (var bw = new BinaryWriter(ms))
            {
                bw.Write(InvIDSrc);
                bw.Write(Unknown1);
                bw.Write(InvPosSrc);
                bw.Write(InvIDDst);
                bw.Write(InvPosDst);
                bw.Write(Count);
                return ms.ToArray();
            }
        }

        public override string ToString() => $"Took {Count} items of a stack, pos {InvPosSrc}->{InvPosDst}, inv {InvIDSrc}->{InvIDDst}, unk {Unknown1}";
    }
}
