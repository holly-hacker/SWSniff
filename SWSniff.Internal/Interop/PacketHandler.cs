using System;
using System.Text;

namespace SWSniff.Internal.Interop
{
    internal class PacketHandler
    {
        public PacketHandler()
        {

        }

        public unsafe void HandleSend(IntPtr socket, IntPtr buf, int len, HookedFunction fn)
        {
            var sb = new StringBuilder();
            byte* ptr = (byte*)buf.ToPointer();

            for (int i = 0; i < len; i++) {
                byte b = *ptr++;
                sb.AppendFormat("{0:X2}-", b);
            }
            
            Console.WriteLine(fn + ": " + sb.ToString().TrimEnd('-'));
        }

        public unsafe void HandleRecv(IntPtr socket, IntPtr buf, int len, HookedFunction fn)
        {
            var sb = new StringBuilder();
            byte* ptr = (byte*)buf.ToPointer();

            for (int i = 0; i < len; i++) {
                byte b = *ptr++;
                sb.AppendFormat("{0:X2}-", b);
            }

            Console.WriteLine(fn + ": " + sb.ToString().TrimEnd('-'));
        }
    }
}
