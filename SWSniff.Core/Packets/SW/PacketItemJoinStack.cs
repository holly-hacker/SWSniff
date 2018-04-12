using System;
using System.Diagnostics;

namespace SWSniff.Core.Packets.SW
{
    public class PacketItemJoinStack : SWPacket
    {
        public byte InvIDSrc, InvIDDst;
        public int Unknown1, Unknown2;
        public short InvPosSrc, InvPosDst;
        public short Count;

        protected override void HandleData(byte[] data)
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

        public override string ToString() => $"Added {Count} items to stack at pos {InvPosSrc}->{InvPosDst}, inv {InvIDSrc}->{InvIDDst}";
    }
}
