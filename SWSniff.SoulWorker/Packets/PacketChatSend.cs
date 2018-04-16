using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using SWSniff.Core.Interfaces;

namespace SWSniff.SoulWorker.Packets
{
    public class PacketChatSend : SWPacket, ICanSerialize
    {
        public byte Channel;
        public string Message;

        public PacketChatSend() { }

        public PacketChatSend(byte ch, string msg)
        {
            Channel = ch;
            Message = msg;
        }

        protected override void Deserialize(byte[] data)
        {
            Debug.Assert(ID == 0x0701);

            if (data.Length >= 3) {
                Channel = data[0];
                short len = BitConverter.ToInt16(data, 1);
                Debug.Assert(len+1 == data.Length-3, "given string length does not match length of data");

                Message = Encoding.Unicode.GetString(data, 3, len-1);
            }
            else Debug.Fail("Unexpected packet length");
        }

        public byte[] Serialize()
        {
            byte[] bufferMsg = Encoding.Unicode.GetBytes(Message);

            using (var ms = new MemoryStream(1 + 2 + bufferMsg.Length + 2))
            using (var bw = new BinaryWriter(ms)) {
                bw.Write(Channel);
                bw.Write((short)(bufferMsg.Length - 1));
                bw.Write(bufferMsg);
                bw.Write((short)0x0000);

                return ms.ToArray();    //TODO: can I use getbuffer? on this or any of the Serialize implementations?
            }
        }

        public override string ToString() => $"Sent chat message in channel {Channel}: {Message}";
    }
}
