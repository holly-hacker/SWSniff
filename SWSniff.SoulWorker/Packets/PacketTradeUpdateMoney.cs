using System;
using System.Diagnostics;
using SWSniff.Core.Interfaces;

namespace SWSniff.SoulWorker.Packets
{
    public class PacketTradeUpdateMoney : SWPacket, ICanSerialize
    {
        public long Amount;

        public PacketTradeUpdateMoney() { }

        public PacketTradeUpdateMoney(long amount)
        {
            Amount = amount;
        }

        protected override void Deserialize(byte[] data)
        {
            Debug.Assert(ID == 0x0A04);

            if (data.Length == 8)
                Amount = BitConverter.ToInt64(data, 0);
        }

        public byte[] Serialize() => BitConverter.GetBytes(Amount);

        public override string ToString() => $"Updated trade amount to {Amount}";
    }
}
