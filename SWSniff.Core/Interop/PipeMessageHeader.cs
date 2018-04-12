using System.Runtime.InteropServices;

namespace SWSniff.Core.Interop
{
    [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Ansi)]
    public struct PipeMessageHeader
    {
        public const int Size = 14;

        public PipeCommand Command;
        public PipeFunction Function;
        public int SocketId;
        public int DataSize;
        public int Extra;
    }
}
