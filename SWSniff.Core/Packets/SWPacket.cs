using System.Diagnostics;
using System.IO;

namespace SWSniff.Core.Packets
{
    //TODO: make abstract abd inherit from this
    public class SWPacket
    {
        public byte ID0, ID1, ID2;
        public byte[] Data;

        public static SWPacket Parse(byte[] allData)
        {
            using (var ms = new MemoryStream(allData))
            using (var br = new BinaryReader(ms)) {
                br.ReadInt16(); //likely version
                var len = br.ReadInt16();
                var id0 = br.ReadByte();
                var id1 = br.ReadByte();
                var id2 = br.ReadByte();
                byte[] packetData = br.ReadBytes(len - 7);
                Debug.Assert(ms.Position == ms.Length, "Not at end of stream after reading packet");

                var p = new SWPacket();
                p.ID0 = id0;
                p.ID1 = id1;
                p.ID2 = id2;
                p.Data = packetData;
                return p;
            }
        }
    }
}
