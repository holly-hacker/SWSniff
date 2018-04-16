using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using SWSniff.Core.Interfaces;

namespace SWSniff.SoulWorker.Packets
{
    public class PacketChatGmCommand : SWPacket, ICanSerialize
    {
        public string Message;

        public PacketChatGmCommand() { }

        public PacketChatGmCommand(string msg)
        {
            Message = msg;
        }

        protected override void Deserialize(byte[] data)
        {
            Debug.Assert(ID == 0x070A);

            if (data.Length >= 2)
            {
                short len = BitConverter.ToInt16(data, 1);
                Debug.Assert(len + 1 == data.Length - 2, "given string length does not match length of data");

                Message = Encoding.Unicode.GetString(data, 3, len - 1);
            }
            else Debug.Fail("Unexpected packet length");
        }

        public byte[] Serialize()
        {
            byte[] bufferMsg = Encoding.Unicode.GetBytes(Message);

            using (var ms = new MemoryStream(2 + bufferMsg.Length + 2))
            using (var bw = new BinaryWriter(ms)) {
                bw.Write((short)(bufferMsg.Length - 1));
                bw.Write(bufferMsg);
                bw.Write((short)0x0000);

                return ms.ToArray();
            }
        }

        public override string ToString() => $"Sent GM message: {Message}";
    }
}
