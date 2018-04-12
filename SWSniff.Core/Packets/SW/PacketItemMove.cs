using System;
using System.Diagnostics;

namespace SWSniff.Core.Packets.SW
{
    public class PacketItemMove : SWPacket
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

        public override string ToString() => $"Moved items from pos {InvPosSrc}->{InvPosDst}, inv {InvIDSrc}->{InvIDDst}";
    }
}
