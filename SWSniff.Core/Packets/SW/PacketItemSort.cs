using System.Diagnostics;

namespace SWSniff.Core.Packets.SW
{
    public class PacketItemSort : SWPacket
    {
        public byte InvID;

        protected override void HandleData(byte[] data)
        {
            Debug.Assert(ID == 0x0825);

            if (data.Length == 1)
                InvID = data[0];
            else Debug.Fail("Unexpected packet length");
        }

        public override string ToString() => $"Sorted inventory {InvID}";
    }
}
