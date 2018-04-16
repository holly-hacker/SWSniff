using System;
using System.Diagnostics;
using SWSniff.Core.Interfaces;

namespace SWSniff.SoulWorker.Packets
{
    public class PacketTradeUpdateItem : SWPacket, ICanSerialize
    {
        public byte Action, InvID;
        public short InvSlot;

        public PacketTradeUpdateItem() { }

        public PacketTradeUpdateItem(byte action, byte invID, short invSlot)
        {
            Action = action;
            InvID = invID;
            InvSlot = invSlot;
        }
        
        protected override void Deserialize(byte[] data)
        {
            Debug.Assert(ID == 0x0A03);

            if (data.Length == 4) {
                Action = data[0];
                InvID = data[1];
                InvSlot = BitConverter.ToInt16(data, 2);
            }
        }

        public byte[] Serialize()
        {
            byte[] buffer = new byte[4];
            buffer[0] = Action;
            buffer[1] = InvID;
            buffer[2] = (byte)InvSlot;
            buffer[3] = (byte)(InvSlot >> 8);
            return buffer;
        }

        public override string ToString() => $"x item in slot {InvSlot} from inventory {InvID}";
    }
}
