using System;

namespace Keygen
{
    public class Progress : EventArgs
    {
        public int V2 { get; set; }

        public Progress(int v1)
        {
            V2 = v1;
        }
    }
}