using System;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using SWSniff.Internal.Hooking;
using SWSniff.Internal.Interop;

namespace SWSniff.Internal
{
    public static unsafe class InjectStart
    {
        [DllImport("kernel32")]
        private static extern bool AllocConsole();

        private delegate int SendDelegate(IntPtr socket, byte* buf, int len, SocketFlags flags);
        private delegate int RecvDelegate(IntPtr socket, byte* buf, int len, SocketFlags flags);
        private delegate int WSARecvDelegate(IntPtr socket, WSABuffer* buffers, int bufferCount, int* numberOfBytesRecvd, SocketFlags* flags, void* overlapped, void* completionRoutine);
        private delegate int WSASendDelegate(IntPtr socket, WSABuffer* buffers, int bufferCount, int* numberOfBytesSent, SocketFlags* flags, void* overlapped, void* completionRoutine);

        private static PacketHandler _packetHandler;
        private static PipeManager _pipeManager;
        private static HookWrapper<SendDelegate> _sendHook;
        private static HookWrapper<RecvDelegate> _recvHook;
        private static HookWrapper<WSASendDelegate> _wsaSendHook;
        private static HookWrapper<WSARecvDelegate> _wsaRecvHook;

        public static int Main(string s)
        {
#if DEBUG
            AllocConsole();
#endif
            Console.WriteLine("Initializing");
            Console.WriteLine("IntPtr size: " + IntPtr.Size);
            _pipeManager = new PipeManager();
            _packetHandler = new PacketHandler(_pipeManager);

            Console.WriteLine("Creating hook");
            _recvHook = new HookWrapper<RecvDelegate>("Ws2_32.dll", "recv", 16);
            _sendHook = new HookWrapper<SendDelegate>("Ws2_32.dll", "send", 19);
            _wsaSendHook = new HookWrapper<WSASendDelegate>("Ws2_32.dll", "WSASend");
            _wsaRecvHook = new HookWrapper<WSARecvDelegate>("Ws2_32.dll", "WSARecv");

            Console.WriteLine("Applying hook");
            _sendHook.Apply(SendTarget);
            _recvHook.Apply(RecvTarget);
            _wsaSendHook.Apply(WSASendTarget);
            _wsaRecvHook.Apply(WSARecvTarget);

            Console.WriteLine("Connect back to main exe");
            _pipeManager.Connect();

            Console.WriteLine("Reached end of main, will enter loop to prevent unloading");
            while (true)
                Thread.Sleep(1000);
        }

        private static int SendTarget(IntPtr socket, byte* buf, int len, SocketFlags flags)
        {
            _packetHandler.HandleSend(socket, buf, len, flags);
            return _sendHook.OriginalFunction(socket, buf, len, flags);
        }

        private static int RecvTarget(IntPtr socket, byte* buf, int len, SocketFlags flags)
        {
            _packetHandler.HandleRecv(socket, buf, len, flags);
            return _recvHook.OriginalFunction(socket, buf, len, flags);
        }

        private static unsafe int WSASendTarget(IntPtr socket, WSABuffer* buffers, int bufferCount, int* numberOfBytesSent, SocketFlags* flags, void* overlapped, void* completionRoutine)
        {
            _packetHandler.HandleWSASend(socket, buffers, bufferCount, *flags);
            return _wsaSendHook.OriginalFunction(socket, buffers, bufferCount, numberOfBytesSent, flags, overlapped, completionRoutine);
        }

        private static unsafe int WSARecvTarget(IntPtr socket, WSABuffer* buffers, int bufferCount, int* numberOfBytesRecvd, SocketFlags* flags, void* overlapped, void* completionRoutine)
        {
            _packetHandler.HandleWSARecv(socket, buffers, bufferCount, *flags);
            return _wsaRecvHook.OriginalFunction(socket, buffers, bufferCount, numberOfBytesRecvd, flags, overlapped, completionRoutine);
        }
    }
}
