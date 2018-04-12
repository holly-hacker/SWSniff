using System;
using System.Diagnostics;
using System.Text;

namespace SWSniff.Core.Packets.SW
{
    public class PacketChatSend : SWPacket
    {
        public byte Channel;
        public string Message;

        protected override void HandleData(byte[] data)
        {
            Debug.Assert(ID == 0x0701);

            if (data.Length >= 3) {
                Channel = data[0];
                short len = BitConverter.ToInt16(data, 1);

                Message = Encoding.Unicode.GetString(data, 3, data.Length - 3);
            }
            else Debug.Fail("Unexpected packet length");
        }

        public override string ToString() => $"Sent chat message in channel {Channel}: {Message}";
    }
}
