using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace XenoStealerLib.Utils
{
    public static class FileLockInfo//thx to https://stackoverflow.com/questions/317071/how-do-i-find-out-which-process-is-locking-a-file-using-net
    {
        private const int RmRebootReasonNone = 0;

        public static List<int> GetProcessesIdsLockingFile(string path)
        {
            uint handle;
            string key = Guid.NewGuid().ToString();
            int res = NativeMethods.RmStartSession(out handle, 0, key);

            if (res != 0) throw new Exception("Could not begin restart session.  Unable to determine file locker.");

            try
            {
                const int MORE_DATA = 234;
                uint pnProcInfoNeeded, pnProcInfo = 0, lpdwRebootReasons = RmRebootReasonNone;

                string[] resources = { path }; // Just checking on one resource.

                res = NativeMethods.RmRegisterResources(handle, (uint)resources.Length, resources, 0, null, 0, null);

                if (res != 0) throw new Exception("Could not register resource.");

                //Note: there's a race condition here -- the first call to RmGetList() returns
                //      the total number of process. However, when we call RmGetList() again to get
                //      the actual processes this number may have increased.
                res = NativeMethods.RmGetList(handle, out pnProcInfoNeeded, ref pnProcInfo, null, ref lpdwRebootReasons);

                if (res == MORE_DATA)
                {
                    return EnumerateProcesses(pnProcInfoNeeded, handle, lpdwRebootReasons);
                }
                else if (res != 0) throw new Exception("Could not list processes locking resource. Failed to get size of result.");
            }
            finally
            {
                NativeMethods.RmEndSession(handle);
            }

            return new List<int>();
        }

        private static List<int> EnumerateProcesses(uint pnProcInfoNeeded, uint handle, uint lpdwRebootReasons)
        {
            var processes = new List<int>();
            // Create an array to store the process results
            var processInfo = new RM_PROCESS_INFO[pnProcInfoNeeded];
            var pnProcInfo = pnProcInfoNeeded;

            // Get the list
            var res = NativeMethods.RmGetList(handle, out pnProcInfoNeeded, ref pnProcInfo, processInfo, ref lpdwRebootReasons);

            if (res != 0) throw new Exception("Could not list processes locking resource.");
            for (int i = 0; i < pnProcInfo; i++)
            {
                try
                {
                    processes.Add(processInfo[i].Process.dwProcessId);
                }
                catch (ArgumentException) { }
            }
            
            return processes;
        }
    }
}
