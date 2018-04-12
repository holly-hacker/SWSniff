using System;
using System.IO;
using SWSniff.Core;
using SWSniff.Core.Packets;
using SWSniff.Core.Packets.SW;

namespace SWSniff
{
    internal static class Program
    {
        private static string DirLog;
        private static DateTime StartTime;
        private static int LastSockId;

        private static void Main(string[] args)
        {
            Console.WriteLine("Init...");
            Sniffer s = new Sniffer();
            Directory.CreateDirectory(DirLog = $"Capture_{StartTime = DateTime.Now:yyyyMMdd_hhmmss}");
            s.PacketAction += OnPacketAction;

            Console.WriteLine("Waiting for proc...");
            s.WaitForProcess();

            Console.WriteLine("Starting...");
            s.Start();

            Console.WriteLine("Started, press enter to send a packet");
            Console.ReadLine();
            s.Inject(PacketType.ClientItemMoveMoney, new PacketItemMoveMoney(false, 123), LastSockId);

            Console.WriteLine("Press enter to exit");
            Console.ReadLine();
        }

        private static void OnPacketAction(object sender, SnifferEventArgs e)
        {
            SWPacket p = e.Packet;
            LastSockId = e.SocketId;

            PacketLogConsole(p, e.Outgoing);
            PacketLogDisk(p, e.Outgoing);
        }

        private static void PacketLogConsole(SWPacket p, bool outgoing)
        {
            if (p.ID == 0x0106 || p.PacketType() == PacketType.ClientCharacterUpdateSpecialOptionList) return;  //keepalive-ish stuff
            //if (p.ID == 0x0501 || p.ID == 0x0503) return;  //movement
            Console.WriteLine($"{(outgoing ? "[OUT]" : "[IN] ")} {p}");
        }

        private static void PacketLogDisk(SWPacket p, bool outgoing)
        {
            if (p.ID == 0x0106 || p.PacketType() == PacketType.ClientCharacterUpdateSpecialOptionList) return;  //keepalive-ish stuff
            if (p.ID == 0x0501 || p.ID == 0x0503) return;  //movement
            string fileName = $"{(int)(DateTime.Now - StartTime).TotalMilliseconds:D7}ms_{(outgoing ? "Out" : "In_")}_{p.IDString()}_len{p.Data.Length}.bin";
            File.WriteAllBytes(Path.Combine(DirLog, fileName), p.Data);
        }
    }
}
