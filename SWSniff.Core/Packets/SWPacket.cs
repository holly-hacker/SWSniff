using System.Diagnostics;
using System.IO;
using System.Linq;
using SWSniff.Core.Packets.SW;

namespace SWSniff.Core.Packets
{
    public abstract class SWPacket
    {
        public byte ID0;
        public byte ID1;
        public byte ID2;
        public ushort ID => (ushort)(ID2 + (ID1 << 8));
        public byte[] Data;

        public static SWPacket Parse(byte[] allData)
        {
#if DEBUG
            var beforeDecrypt = allData.Clone();
#endif
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

                SWPacket ret;
                ret = GetCorrectPacket((PacketType)(id2 + (id1 << 8)));

                ret.ID0 = id0;
                ret.ID1 = id1;
                ret.ID2 = id2;
                ret.Data = packetData;
                ret.HandleData(ret.Data);
                return ret;

            }
        }

        private static SWPacket GetCorrectPacket(PacketType t)
        {
            switch (t) {
                case PacketType.ClientItemMove: return new PacketItemMove();
                case PacketType.ClientItemJoinStack: return new PacketItemJoinStack();
                case PacketType.ClientItemSplitStack: return new PacketItemSplitStack();
                case PacketType.ClientItemMoveMoney: return new PacketItemMoveMoney();
                case PacketType.ClientItemSort: return new PacketItemSort();

                case PacketType.ClientShopBuyItem:  return new PacketShopBuyItem();
                case PacketType.ClientShopSellItem: return new PacketShopSellItem();

                default: return new GenericSWPacket();
            }

        }

        protected abstract void HandleData(byte[] data);

        public override string ToString()
        {
            string dataString = Data.Length == 0 ? string.Empty : ": " + string.Join("-", Data.Select(x => x.ToString("X2")));
            return $"{this.IDString()}{dataString}";
        }

        private static void DecryptArray(byte[] arr)
        {
            const int arrOffset = 5;
            byte xorOffset = arr[0];
            for (int i = 0; i < arr.Length - arrOffset; i++)
                arr[i + arrOffset] ^= Constants.XorKey[xorOffset*4 + i%3];
        }
    }
    
    public class GenericSWPacket : SWPacket
    {
        protected override void HandleData(byte[] data) { }
    }
}
