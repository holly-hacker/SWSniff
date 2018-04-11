namespace SWSniff.Core.Interop
{
    public enum PipeCommand : byte
    {
        Data = 0x1,
        StructData = 0x2,
        NoFilterData = 0x3,
        NoFilterStructData = 0x4,
        NoData = 0x5,
        DnsData = 0x6,
        DnsStructData = 0x7,
        Init = 0x8,
        DeInit = 0x9,

        Query = 0xF5,
        UnFreeze = 0xF6,
        Freeze = 0xF7,
        Filter = 0xF8,
        Recv = 0xF9,
        Inject = 0xFA,
        DisableFilter = 0xFB,
        EnableFilter = 0xFC,
        DisableMonitor = 0xFD,
        EnableMonitor = 0xFE,
        UnloadDLL = 0xFF,
    }

    public enum PipeFunction : byte
    {
        InitDecrypt = 1,

        FuncNull = 0,
        FuncWsaSend = 1,
        FuncWsaRecv = 2,
        FuncSend = 3,
        FuncRecv = 4,
        FuncWsaSendTo = 5,
        FuncWsaRecvFrom = 6,
        FuncSendTo = 7,
        FuncRecvFrom = 8,
        FuncWsaSendDisconnect = 9,
        FuncWsaRecvDisconnect = 10,
        FuncWsaAccept = 11,
        FuncAccept = 12,
        FuncWsaConnect = 13,
        FuncConnect = 14,
        FuncWsaSocketWIn = 15,
        FuncWsaSocketWOut = 16,
        FuncBind = 17,
        FuncCloseSocket = 18,
        FuncListen = 19,
        FuncShutdown = 20,

        ConnWsaSendTo = 21,
        ConnWsaRecvFrom = 22,
        ConnSendTo = 23,
        ConnRecvFrom = 24,

        DnsGetHostByNameOut = 25,
        DnsGetHostByNameIn = 26,
        DnsGetHostByaAdrOut = 27,
        DnsGetHostByAddrIn = 28,
        DnsWsaAsyncGetHostByNameOut = 29,
        DnsWsaAsyncGetHostByNameIn = 30,
        DnsWsaAsyncGetHostByAddrOut = 31,
        DnsWsaAsyncGetHostByAddrIn = 32,
        DnsGetHostName = 33,

        FuncWsaCleanup = 34,
        FuncSocketIn = 35,
        FuncSocketOut = 36,
        FuncGetSockName = 37,
        FuncGetPeerName = 38,
    }
}
