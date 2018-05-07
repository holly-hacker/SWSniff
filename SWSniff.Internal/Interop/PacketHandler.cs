using System;
using System.Diagnostics;
using System.Net.Sockets;
using System.Text;

namespace SWSniff.Internal.Interop
{
    internal class PacketHandler
    {
        private readonly PipeManager _pipeMan;

        public PacketHandler(PipeManager pipeMan)
        {
            _pipeMan = pipeMan;
        }

        public void HandleSend(IntPtr socket, IntPtr buf, int len, SocketFlags flags)
        {
            const PacketFunction fn = PacketFunction.Send;
            DebugLog(buf, len, flags, fn);
            _pipeMan.SendPacketDetected(fn, socket, ReadMemoryBuffer(buf, len));
        }

        public void HandleRecv(IntPtr socket, IntPtr buf, int len, SocketFlags flags)
        {
            const PacketFunction fn = PacketFunction.Recv;
            DebugLog(buf, len, flags, fn);
            _pipeMan.SendPacketDetected(fn, socket, ReadMemoryBuffer(buf, len));
        }

        public unsafe void HandleWSASend(IntPtr socket, IntPtr wsaBuf, int bufferCount, SocketFlags flags)
        {
            const PacketFunction fn = PacketFunction.WSASend;
            for (int i = 0; i < bufferCount; i++) {
                var bufPtr = (WSABuffer*)wsaBuf + i;
                DebugLog((*bufPtr).Data, (*bufPtr).Length, flags, fn);
                _pipeMan.SendPacketDetected(fn, socket, ReadMemoryBuffer((*bufPtr).Data, (*bufPtr).Length));
            }
        }

        public unsafe void HandleWSARecv(IntPtr socket, IntPtr wsaBuf, int bufferCount, SocketFlags flags)
        {
            const PacketFunction fn = PacketFunction.WSARecv;
            for (int i = 0; i < bufferCount; i++) {
                var bufPtr = (WSABuffer*)wsaBuf + i;
                DebugLog((*bufPtr).Data, (*bufPtr).Length, flags, fn);
                _pipeMan.SendPacketDetected(fn, socket, ReadMemoryBuffer((*bufPtr).Data, (*bufPtr).Length));
            }
        }

        private struct WSABuffer
        {
            public int Length;
            public IntPtr Data;
        }

        private static unsafe byte[] ReadMemoryBuffer(IntPtr buf, int len)
        {
            byte[] buffer = new byte[len];
            byte* ptr = (byte*)buf.ToPointer();
            for (int i = 0; i < len; i++)
                buffer[i] = *ptr++;
            return buffer;
        }

        [Conditional("DEBUG")]
        private static unsafe void DebugLog(IntPtr buf, int len, SocketFlags flags, PacketFunction fn)
        {
            var sb = new StringBuilder();
            byte* ptr = (byte*)buf.ToPointer();

            for (int i = 0; i < len; i++)
                sb.AppendFormat("{0:X2}-", *ptr++);

            string s = sb.ToString().TrimEnd('-');
            if (s.Length >= 0x200)
                s = s.Substring(0, 0x200) + "... [" + len + "]";

            Console.WriteLine(fn + ": " + s + " (" + flags + ")");
        }
    }
}
