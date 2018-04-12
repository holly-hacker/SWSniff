using System.IO.Pipes;

namespace SWSniff.Core.Interop
{
    internal class PipeMessage
    {
        public PipeMessageHeader Header;
        public readonly byte[] Data;

        public bool HasData => Header.DataSize != 0;
        
        public PipeMessage(PipeCommand cmd, PipeFunction fun = 0, byte[] data = null) : this(cmd, fun, 0, data, 0) { }

        public PipeMessage(PipeCommand cmd, PipeFunction fun, int sockid, byte[] data, int extra = 0)
        {
            Header = new PipeMessageHeader {
                Command = cmd,
                Function = fun,
                SocketId = sockid,
                DataSize = data?.Length ?? 0,
                Extra = extra,
            };

            Data = data;
        }

        private PipeMessage(PipeMessageHeader hdr, byte[] data)
        {
            Header = hdr;
            Data = data;
        }

        public static bool ReadFromPipe(NamedPipeServerStream pipe, out PipeMessage msg)
        {
            msg = null;
            byte[] bufferMsgHdr = new byte[PipeMessageHeader.Size];

            if (pipe.Read(bufferMsgHdr, 0, PipeMessageHeader.Size) != 0) {
                var hdr = (PipeMessageHeader)GeneralHelper.DeSerializeObj(bufferMsgHdr, typeof(PipeMessageHeader));

                //check for data
                byte[] bufferData = null;
                if (hdr.DataSize != 0) {
                    bufferData = new byte[hdr.DataSize];
                    pipe.Read(bufferData, 0, bufferData.Length);
                }

                msg = new PipeMessage(hdr, bufferData);
                return true;
            }
            else return false;
        }

        public void Send(NamedPipeClientStream pipe)
        {
            pipe.Write(GeneralHelper.SerializeObj(Header), 0, PipeMessageHeader.Size);

            if (Data != null)
                pipe.Write(Data, 0, Data.Length);
        }
    }
}
