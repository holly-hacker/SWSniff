using System;
using System.Net.Sockets;
using System.Text;

namespace SWSniff.Internal.Interop
{
    internal class PacketHandler
    {
        public PacketHandler()
        {

        }

        public unsafe void HandleSend(IntPtr socket, IntPtr buf, int len, SocketFlags flags, HookedFunction fn)
        {
            var sb = new StringBuilder();
            byte* ptr = (byte*)buf.ToPointer();

            for (int i = 0; i < len; i++) {
                byte b = *ptr++;
                sb.AppendFormat("{0:X2}-", b);
            }

            string s = sb.ToString().TrimEnd('-');
            if (s.Length >= 0x200)
                s = s.Substring(0, 0x200) + "...";

            Console.WriteLine(fn + ": " + s + " (" + flags + ")");
        }

        public unsafe void HandleRecv(IntPtr socket, IntPtr buf, int len, SocketFlags flags, HookedFunction fn)
        {
            var sb = new StringBuilder();
            byte* ptr = (byte*)buf.ToPointer();

            for (int i = 0; i < len; i++) {
                byte b = *ptr++;
                sb.AppendFormat("{0:X2}-", b);
            }

            string s = sb.ToString().TrimEnd('-');
            if (s.Length >= 0x200)
                s = s.Substring(0, 0x200) + "...";

            Console.WriteLine(fn + ": " + s + " (" + flags + ")");
        }
    }
}
