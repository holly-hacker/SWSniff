using System;
using System.IO.Pipes;

namespace SWSniff.Internal.Interop
{
    internal class PipeManager
    {
        private readonly NamedPipeClientStream _pipeOut;

        public PipeManager()
        {
            _pipeOut = new NamedPipeClientStream(Constants.PipeNameIn);
        }

        public void Connect()
        {
            _pipeOut.Connect();
        }

        public void SendPacketDetected(PacketFunction fn, IntPtr socket, byte[] readBuffer)
        {
            byte[] header = new byte[PacketHeader.PacketLength];
            header[0] = (byte)PacketCommand.ReadonlyPacketInfo;
            header[1] = (byte)fn;
            BitConverter.GetBytes(socket.ToInt32()).CopyTo(header, 2);
            BitConverter.GetBytes(readBuffer.Length).CopyTo(header, 6);
            _pipeOut.Write(header, 0, PacketHeader.PacketLength);
            _pipeOut.Write(readBuffer, 0, readBuffer.Length);
        }
    }
}
