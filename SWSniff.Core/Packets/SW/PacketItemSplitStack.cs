using System;
using System.Diagnostics;

namespace SWSniff.Core.Packets.SW
{
    public class PacketItemSplitStack : SWPacket
    {
        private byte InvIDSrc, InvIDDst;
        private int Unknown1;
        private short InvPosSrc, InvPosDst;
        private short Count;

        protected override void HandleData(byte[] data)
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

        public override string ToString() => $"Took {Count} items of a stack, pos {InvPosSrc}->{InvPosDst}, inv {InvIDSrc}->{InvIDDst}";
    }
}
