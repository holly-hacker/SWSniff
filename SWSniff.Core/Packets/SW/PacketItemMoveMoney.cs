using System;
using System.Diagnostics;

namespace SWSniff.Core.Packets.SW
{
    public class PacketItemMoveMoney : SWPacket
    {
        private bool Depositing;
        private long Amount;

        protected override void HandleData(byte[] data)
        {
            Debug.Assert(ID == 0x0824);

            if (data.Length == 9) {
                Depositing = data[0] > 0;
                Amount = BitConverter.ToInt64(data, 1);
            }
            else Debug.Fail("Unexpected packet length");
        }

        public override string ToString() => Depositing ? $"Depositing {Amount}dz to bank" : $"Withdrawing {Amount}dz from bank";
    }
}
