using System;
using System.Diagnostics;
using SWSniff.Core;
using SWSniff.Core.Interfaces;
using SWSniff.Core.Interop;
using SWSniff.SoulWorker.Packets;

namespace SWSniff.SoulWorker
{
    public class SWSniffer : SnifferBase
    {
        public event PacketEventDelegate PacketAction;
        public delegate void PacketEventDelegate(object sender, SnifferEventArgs e);

        public SWSniffer() : base(Constants.ProcName) { }

        public void Inject(PacketType t, ICanSerialize p, int sockId)
        {
            //serialize the packet
            byte[] dataPacket = p.Serialize();
            Inject(t, dataPacket, sockId);
        }

        public void Inject(PacketType t, byte[] dataPacket, int sockId)
        {
            short len = (short)(dataPacket.Length + 7);

            //get buffer to copy in the final byte array
            byte[] buffer = new byte[len];

            buffer[0] = 2;
            buffer[1] = 0;
            buffer[2] = (byte)(len >> 0);
            buffer[3] = (byte)(len >> 8);
            buffer[4] = 1;
            buffer[5] = t.ID1();
            buffer[6] = t.ID2();

            //fill in the data
            Array.Copy(dataPacket, 0, buffer, 7, dataPacket.Length);

            GeneralHelper.XorPacket(buffer);

            Inject(buffer, sockId);
        }

        /// <summary> Reads all packets from the message and invokes the event handlers. </summary>
        protected override void HandlePacket(PipeMessage msg, bool outgoing)
        {
            Debug.Assert(msg.HasData);
            var data = msg.Data;

            int packetStart = 0;
            while (packetStart < data.Length)
            {
                //read cleartext packet header
                Debug.Assert(BitConverter.ToInt16(data, packetStart + 0) == 0x0002, "Unknown xor offset");
                short packetLen = BitConverter.ToInt16(data, packetStart + 2);

                //extract packet and parse it
                byte[] slice = new byte[packetLen]; //TODO: C# 7 slicing
                Array.Copy(data, packetStart, slice, 0, packetLen);
                SWPacket p = SWPacket.Parse(slice);
                PacketAction?.Invoke(this, new SnifferEventArgs(p, outgoing, msg.Header.SocketId));

                //update packet start
                packetStart += packetLen;
            }
        }
    }
}
