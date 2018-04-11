using System.Runtime.InteropServices;

namespace SWSniff.Core.Interop
{
    [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Ansi)]
    public struct PipeMessageHeader
    {
        //TODO: wrap this struct

        public PipeCommand Command;
        public PipeFunction Function;
        public int SocketId;
        public int DataSize;
        public int Extra;

        public PipeMessageHeader(PipeCommand cmd, PipeFunction fun = 0, byte[] data = null) : this(cmd, fun, 0, data, 0) { }

        public PipeMessageHeader(PipeCommand cmd, PipeFunction fun, int sockid, byte[] data, int extra)
        {
            Command = cmd;
            Function = fun;
            SocketId = sockid;
            DataSize = data?.Length ?? 0;
            Extra = extra;
        }
    }
}
