using System;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using SWSniff.Internal.Hooking;

namespace SWSniff.Internal
{
    public static class InjectStart
    {
        [DllImport("kernel32")]
        private static extern bool AllocConsole();

        private delegate int RecvDelegate(IntPtr socket, IntPtr buf, int len, int flags);
        private delegate int WSASendDelegate(IntPtr socket, IntPtr buffers, int bufferCount, out IntPtr numberOfBytesSent, SocketFlags flags, IntPtr overlapped, IntPtr completionRoutine);

        private static HookWrapper<WSASendDelegate> _wsaSendHook;

        public static int Main(string s)
        {
            AllocConsole();

            Console.WriteLine("Creating hook");
            _wsaSendHook = new HookWrapper<WSASendDelegate>("Ws2_32.dll", "WSASend");

            Console.WriteLine("Applying hook");
            _wsaSendHook.Apply(WSASendTarget);

            Console.WriteLine("Reached end of main");
            return 0;
        }

        public static int WSASendTarget(IntPtr socket, IntPtr buffers, int bufferCount, out IntPtr numberOfBytesSent, SocketFlags flags, IntPtr overlapped, IntPtr completionRoutine)
        {
            // Log stuff here
            Console.WriteLine($"WSASend on socket {socket.ToInt32():X}: 0x{buffers.ToInt32():X8}");

            return _wsaSendHook.OriginalFunction(socket, buffers, bufferCount, out numberOfBytesSent, flags, overlapped, completionRoutine);
        }
    }
}
