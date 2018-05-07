using System;
using System.Diagnostics;
using System.Net.Sockets;
using System.Text;

namespace SWSniff.Internal.Interop
{
    internal unsafe class PacketHandler
    {
        private readonly PipeManager _pipeMan;

        public PacketHandler(PipeManager pipeMan)
        {
            _pipeMan = pipeMan;
        }

        public void HandleSend(IntPtr socket, byte* buf, int len, SocketFlags flags)
        {
            const PacketFunction fn = PacketFunction.Send;
            DebugLog(buf, len, flags, fn);
            _pipeMan.SendPacketDetected(fn, socket, ReadMemoryBuffer(buf, len));
        }

        public void HandleRecv(IntPtr socket, byte* buf, int len, SocketFlags flags)
        {
            const PacketFunction fn = PacketFunction.Recv;
            DebugLog(buf, len, flags, fn);
            _pipeMan.SendPacketDetected(fn, socket, ReadMemoryBuffer(buf, len));
        }

        public void HandleWSASend(IntPtr socket, WSABuffer* wsaBuf, int bufferCount, SocketFlags flags)
        {
            const PacketFunction fn = PacketFunction.WSASend;
            for (int i = 0; i < bufferCount; i++) {
                DebugLog(wsaBuf[i].Data, wsaBuf[i].Length, flags, fn);
                _pipeMan.SendPacketDetected(fn, socket, ReadMemoryBuffer(wsaBuf[i].Data, wsaBuf[i].Length));
            }
        }

        public void HandleWSARecv(IntPtr socket, WSABuffer* wsaBuf, int bufferCount, SocketFlags flags)
        {
            const PacketFunction fn = PacketFunction.WSARecv;
            for (int i = 0; i < bufferCount; i++) {
                DebugLog(wsaBuf[i].Data, wsaBuf[i].Length, flags, fn);
                _pipeMan.SendPacketDetected(fn, socket, ReadMemoryBuffer(wsaBuf[i].Data, wsaBuf[i].Length));
            }
        }

        private static byte[] ReadMemoryBuffer(byte* buf, int len)
        {
            byte[] ret = new byte[len];
            for (int i = 0; i < len; i++)
                ret[i] = buf[i];
            return ret;
        }

        [Conditional("DEBUG")]
        private static void DebugLog(byte* buf, int len, SocketFlags flags, PacketFunction fn)
        {
            var sb = new StringBuilder();

            for (int i = 0; i < len; i++)
                sb.AppendFormat("{0:X2}-", buf[i]);

            string s = sb.ToString().TrimEnd('-');
            if (s.Length >= 0x200)
                s = s.Substring(0, 0x200) + "... [" + len + "]";

            Console.WriteLine(fn + ": " + s + " (" + flags + ")");
        }
    }
}
