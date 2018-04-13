using System;
using System.Diagnostics;
using System.IO;

namespace SWSniff.Core.Packets.SW
{
    public class PacketDropPickUp : SWPacket, ICanSerialize
    {
        public int Unknown1, Unknown2, Unknown3;

        protected override void Deserialize(byte[] data)
        {
            Debug.Assert(ID == 0x1402);

            if (data.Length == 12) {
                Unknown1 = BitConverter.ToInt32(data, 0);
                Unknown2 = BitConverter.ToInt32(data, 4);
                Unknown3 = BitConverter.ToInt32(data, 8);
            }
            else Debug.Fail("Unexpected packet length");
        }

        public byte[] Serialize()
        {
            using (var ms = new MemoryStream(16))
            using (var bw = new BinaryWriter(ms)) {
                bw.Write(Unknown1);
                bw.Write(Unknown2);
                bw.Write(Unknown3);
                return ms.ToArray();
            }
        }

        public override string ToString() => $"Picked up a drop, {Unknown1}, {Unknown2}, {Unknown3:X8}";
    }
}
