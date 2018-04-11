using System;
using SWSniff.Core;

namespace SWSniff
{
    internal static class Program
    {
        private static void Main(string[] args)
        {
            Sniffer s = new Sniffer();
            s.Start();

            Console.WriteLine("Started, press enter to exit");
            Console.ReadLine();
        }
    }
}
