using System.Diagnostics;
using System.IO;

namespace SWSniff.Core.Packets
{
    //TODO: make abstract abd inherit from this
    public class SWPacket
    {
        public byte ID0;
        public byte ID1;
        public byte ID2;
        public ushort ID => (ushort)(ID2 + ID1 << 2);
        public byte[] Data;

        public static SWPacket Parse(byte[] allData)
        {
            DecryptArray(allData);
            using (var ms = new MemoryStream(allData))
            using (var br = new BinaryReader(ms)) {
                br.ReadInt16();
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

        private static void DecryptArray(byte[] arr)
        {
            const int arrOffset = 5;
            byte xorOffset = arr[0];
            for (int i = 0; i < arr.Length - arrOffset; i++)
                arr[i + arrOffset] ^= Constants.XorKey[xorOffset*4 + i%3];
        }
    }
}
