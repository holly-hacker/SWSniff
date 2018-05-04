namespace SWSniff.Internal
{
    internal enum HookedFunction : byte
    {
        None = 0,
        Send = 1,
        Recv = 2,
        WSASend = 3,
        WSARecv = 4,
    }
}
