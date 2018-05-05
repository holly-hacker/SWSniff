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

        public void HandleSend(IntPtr socket, IntPtr buf, int len, SocketFlags flags, PacketFunction fn)
        {
            DebugLog(buf, len, flags, fn);
            _pipeMan.SendPacketDetected(fn, socket, ReadMemoryBuffer(buf, len));
        }

        public void HandleRecv(IntPtr socket, IntPtr buf, int len, SocketFlags flags, PacketFunction fn)
        {
            DebugLog(buf, len, flags, fn);
            _pipeMan.SendPacketDetected(fn, socket, ReadMemoryBuffer(buf, len));
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
