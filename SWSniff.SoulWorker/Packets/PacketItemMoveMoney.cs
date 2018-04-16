using System;
using System.Diagnostics;
using SWSniff.Core.Interfaces;

namespace SWSniff.SoulWorker.Packets
{
    public class PacketItemMoveMoney : SWPacket, ICanSerialize
    {
        public bool Depositing;
        public long Amount;

        public PacketItemMoveMoney() { }

        public PacketItemMoveMoney(bool depositing, long amount)
        {
            Depositing = depositing;
            Amount = amount;
        }

        protected override void Deserialize(byte[] data)
        {
            Debug.Assert(ID == 0x0824);

            if (data.Length == 9) {
                Depositing = data[0] > 0;
                Amount = BitConverter.ToInt64(data, 1);
            }
            else Debug.Fail("Unexpected packet length");
        }

        public byte[] Serialize()
        {
            byte[] buffer = new byte[9];
            buffer[0] = Depositing ? (byte)1 : (byte)0;
            for (int i = 0; i < sizeof(long); i++)
                buffer[1+i] = (byte)(Amount >> 8 * i);

            return buffer;
        }

        public override string ToString() => Depositing ? $"Depositing {Amount}dz to bank" : $"Withdrawing {Amount}dz from bank";
    }
}
