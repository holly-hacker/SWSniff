using System;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using SWSniff.Internal.Hooking;

namespace SWSniff.Internal
{
    public static class InjectStart
    {
        [DllImport("kernel32")]
        private static extern bool AllocConsole();

        private delegate int SendDelegate(IntPtr socket, IntPtr buf, int len, int flags);
        private delegate int RecvDelegate(IntPtr socket, IntPtr buf, int len, int flags);
        private delegate int WSARecvDelegate(IntPtr socket, IntPtr buffers, int bufferCount, out IntPtr numberOfBytesRecvd, SocketFlags flags, IntPtr overlapped, IntPtr completionRoutine);
        private delegate int WSASendDelegate(IntPtr socket, IntPtr buffers, int bufferCount, out IntPtr numberOfBytesSent, SocketFlags flags, IntPtr overlapped, IntPtr completionRoutine);

        private static HookWrapper<SendDelegate> _sendHook;
        private static HookWrapper<RecvDelegate> _recvHook;
        private static HookWrapper<WSASendDelegate> _wsaSendHook;
        private static HookWrapper<WSARecvDelegate> _wsaRecvHook;

        public static int Main(string s)
        {
            AllocConsole();

            Console.WriteLine("Creating hook");
            _recvHook = new HookWrapper<RecvDelegate>("Ws2_32.dll", "recv");
            _sendHook = new HookWrapper<SendDelegate>("Ws2_32.dll", "send");
            _wsaSendHook = new HookWrapper<WSASendDelegate>("Ws2_32.dll", "WSASend");
            _wsaRecvHook = new HookWrapper<WSARecvDelegate>("Ws2_32.dll", "WSARecv");

            Console.WriteLine("Applying hook");
            _sendHook.Apply(SendTarget);
            _recvHook.Apply(RecvTarget);
            _wsaSendHook.Apply(WSASendTarget);
            _wsaRecvHook.Apply(WSARecvTarget);

            Console.WriteLine("Reached end of main, will enter loop to prevent unloading");
            while (true)
                Thread.Sleep(1000);
        }

        private static int SendTarget(IntPtr socket, IntPtr buf, int len, int flags)
        {
            // Log stuff here
            Console.WriteLine($"send on socket {socket.ToInt32():X}: 0x{buf.ToInt32():X8}");

            return _sendHook.OriginalFunction(socket, buf, len, flags);
        }

        private static int RecvTarget(IntPtr socket, IntPtr buf, int len, int flags)
        {
            // Log stuff here
            Console.WriteLine($"recv on socket {socket.ToInt32():X}: 0x{buf.ToInt32():X8}");

            return _recvHook.OriginalFunction(socket, buf, len, flags);
        }

        public static int WSASendTarget(IntPtr socket, IntPtr buffers, int bufferCount, out IntPtr numberOfBytesSent, SocketFlags flags, IntPtr overlapped, IntPtr completionRoutine)
        {
            // Log stuff here
            Console.WriteLine($"WSASend on socket {socket.ToInt32():X}: 0x{buffers.ToInt32():X8}");

            return _wsaSendHook.OriginalFunction(socket, buffers, bufferCount, out numberOfBytesSent, flags, overlapped, completionRoutine);
        }

        private static int WSARecvTarget(IntPtr socket, IntPtr buffers, int bufferCount, out IntPtr numberOfBytesRecvd, SocketFlags flags, IntPtr overlapped, IntPtr completionRoutine)
        {
            // Log stuff here
            Console.WriteLine($"WSARecv on socket {socket.ToInt32():X}: 0x{buffers.ToInt32():X8}");

            return _wsaRecvHook.OriginalFunction(socket, buffers, bufferCount, out numberOfBytesRecvd, flags, overlapped, completionRoutine);
        }
    }
}
