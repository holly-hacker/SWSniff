using System;
using System.Windows.Forms;

namespace SWSniff.Internal
{
    public static class InjectStart
    {
        [STAThread]
        public static int Main(string s)
        {
            MessageBox.Show("Hello from managed code!");

            return 0;
        }
    }
}
