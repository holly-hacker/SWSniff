using System;

namespace SWSniff.SoulWorker
{
    internal static class GeneralHelper
    {
        public static void XorPacket(byte[] arr)
        {
            const int xorStart = 5;
            byte xorIndex = arr[0];
            short len = BitConverter.ToInt16(arr, 2);   //only xor up to the expected length of the packet
            for (int i = 0; i < len - xorStart; i++)
                arr[i + xorStart] ^= Constants.XorKey[xorIndex * 4 + i % 3];
        }
    }
}
