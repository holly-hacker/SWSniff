using System;
using System.Diagnostics;

namespace SWSniff.SoulWorker.Packets
{
    public class PacketMovementMove : SWPacket
    {
        public int Unknown1, Unknown2, Unknown3;
        public byte Unknown4;   //bitfield?
        public short Unknown5;  //0
        public float PosX, PosZ, PosY, Rotation, PosX2, PosZ2, CameraPitch, Speed;

        protected override void Deserialize(byte[] data)
        {
            Debug.Assert(ID == 0x0501);

            if (data.Length == 47) {
                Unknown1 = BitConverter.ToInt32(data, 0);
                Unknown2 = BitConverter.ToInt32(data, 4);
                Unknown3 = BitConverter.ToInt32(data, 8);
                PosX = BitConverter.ToSingle(data, 12);
                PosZ = BitConverter.ToSingle(data, 16);
                PosY = BitConverter.ToSingle(data, 20);
                Rotation = BitConverter.ToSingle(data, 24);
                PosX2 = BitConverter.ToSingle(data, 28);
                PosZ2 = BitConverter.ToSingle(data, 32);
                Unknown4 = data[33];
                CameraPitch = BitConverter.ToSingle(data, 37);
                Speed = BitConverter.ToSingle(data, 41);
                Unknown5 = BitConverter.ToInt16(data, 45);
            }
            else Debug.Fail("Unexpected packet length");
        }

        public override string ToString() => $"[{PosX:F2},{PosY:F2},{PosZ:F2}] Run to, with rot={Rotation:F2}, speed={Speed,4}";
    }
}
