using System;
using System.IO;
using SWSniff.Core;
using SWSniff.Core.Packets;
using SWSniff.Core.Packets.SW;

namespace SWSniff
{
    internal static class Program
    {
        private static string _dirLog;
        private static DateTime _startTime;
        private static int _lastSockId;
        private static Sniffer _s;

        private static void Main(string[] args)
        {
            Console.WriteLine("Init...");
            _s = new Sniffer();
            Directory.CreateDirectory(_dirLog = $"Capture_{_startTime = DateTime.Now:yyyyMMdd_hhmmss}");
            _s.PacketAction += OnPacketAction;

            Console.WriteLine("Waiting for proc...");
            _s.WaitForProcess();

            Console.WriteLine("Starting...");
            _s.Start();

            Console.WriteLine("Started, press enter to send a packet");
            Console.ReadLine();
            _s.Inject(PacketType.ClientItemMoveMoney, new PacketItemMoveMoney(false, 123), _lastSockId);

            Console.WriteLine("Press enter to exit");
            Console.ReadLine();
        }
        
        private static void OnPacketAction(object sender, SnifferEventArgs e)
        {
            SWPacket p = e.Packet;
            _lastSockId = e.SocketId;

            PacketLogConsole(p, e.Outgoing);
            PacketLogDisk(p, e.Outgoing);
        }

        private static void PacketLogConsole(SWPacket p, bool outgoing)
        {
            if (p.ID == 0x0106 || p.PacketType() == PacketType.ClientCharacterUpdateSpecialOptionList) return;  //keepalive-ish stuff
            if ((p.ID & 0xFF00) == 0x0500) return;  //movement
            Console.WriteLine($"{(outgoing ? "[OUT]" : "[IN] ")} {p}");
        }

        private static void PacketLogDisk(SWPacket p, bool outgoing)
        {
            if (p.ID == 0x0106 || p.PacketType() == PacketType.ClientCharacterUpdateSpecialOptionList) return;  //keepalive-ish stuff
            if ((p.ID & 0xFF00) == 0x0500) return;  //movement
            string fileName = $"{(int)(DateTime.Now - _startTime).TotalMilliseconds:D7}ms_{(outgoing ? "Out" : "In_")}_{p.IDString()}_len{p.Data.Length}.bin";
            File.WriteAllBytes(Path.Combine(_dirLog, fileName), p.Data);
        }
    }
}
