using System;
using SWSniff.Internal.Hooking;

namespace SWSniff.Internal
{
    public static class InjectStart
    {
        [STAThread]
        public static int Main(string s)
        {
            var hook = new Hook("Ws2_32.dll", "recv");

            return 0;
        }
    }
}
