using System;
using SWSniff.Core;

namespace SWSniff
{
    internal static class Program
    {
        private static void Main(string[] args)
        {
            Console.WriteLine("Init...");
            Sniffer s = new Sniffer();

            Console.WriteLine("Waiting for proc...");
            s.WaitForProcess();

            Console.WriteLine("Starting...");
            s.Start();

            Console.WriteLine("Started, press enter to exit");
            Console.ReadLine();
        }
    }
}
