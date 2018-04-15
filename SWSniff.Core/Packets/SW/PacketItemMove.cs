using System;
using System.Diagnostics;
using System.IO;

namespace SWSniff.Core.Packets.SW
{
    public class PacketItemMove : SWPacket, ICanSerialize
    {
        public byte InvIDSrc, InvIDDst;
        public int Unknown1, Unknown2;
        public short InvPosSrc, InvPosDst;

        protected override void Deserialize(byte[] data)
        {
            Debug.Assert(ID == 0x0802);

            if (data.Length == 14)
            {
                InvIDSrc = data[0];
                Unknown1 = BitConverter.ToInt32(data, 1);
                InvPosSrc = BitConverter.ToInt16(data, 5);
                InvIDDst = data[7];
                Unknown2 = BitConverter.ToInt32(data, 8);
                InvPosDst = BitConverter.ToInt16(data, 12);
            }
            else Debug.Fail("Unexpected packet length");
        }

        public byte[] Serialize()
        {
            using (var ms = new MemoryStream(14))
            using (var bw = new BinaryWriter(ms)) {
                bw.Write(InvIDSrc);
                bw.Write(Unknown1);
                bw.Write(InvPosSrc);
                bw.Write(InvIDDst);
                bw.Write(Unknown2);
                bw.Write(InvPosDst);
                return ms.ToArray();
            }
        }

        public override string ToString() => $"Moved items from pos {InvPosSrc}->{InvPosDst}, inv {InvIDSrc}->{InvIDDst} (unk: {Unknown1} -> {Unknown2})";
    }
}
