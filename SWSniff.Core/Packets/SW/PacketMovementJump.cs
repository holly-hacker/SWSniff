using System;
using System.Diagnostics;

namespace SWSniff.Core.Packets.SW
{
    public class PacketMovementJump : SWPacket
    {
        public int Unknown1, Unknown2, Unknown3, Unknown4, Unknown5;
        public float PosX, PosZ, PosY, Rotation, PosX2, PosZ2;

        protected override void Deserialize(byte[] data)
        {
            Debug.Assert(ID == 0x0505);

            if (data.Length == 44) {
                Unknown1 = BitConverter.ToInt32(data, 0);
                Unknown2 = BitConverter.ToInt32(data, 4);
                Unknown3 = BitConverter.ToInt32(data, 8);
                PosX = BitConverter.ToSingle(data, 12);
                PosZ = BitConverter.ToSingle(data, 16);
                PosY = BitConverter.ToSingle(data, 20);
                Rotation = BitConverter.ToSingle(data, 24);
                PosX2 = BitConverter.ToSingle(data, 28);
                PosZ2 = BitConverter.ToSingle(data, 32);
                Unknown4 = BitConverter.ToInt32(data, 36);
                Unknown5 = BitConverter.ToInt32(data, 40);
            }
            else Debug.Fail("Unexpected packet length");
        }

        public override string ToString() => $"[{PosX:F2},{PosY:F2},{PosZ:F2}] Jump";
    }
}
