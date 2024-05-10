using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace XenoStealerLib.Utils
{
    public static class SimpleProcessStuff
    {
        public static bool isCurrentProcessUnderPid(int pid)
        {
            int currentPid = (int)NativeMethods.GetCurrentProcessId();
            if (currentPid == pid)
            {
                return true;
            }
            int lastPid = 0;
            int ParentPid = ParentProcessUtil.GetParentProcessId(currentPid);
            while (ParentPid != 0 && ParentPid != lastPid)
            {
                if (ParentPid == pid)
                {
                    return true;
                }
                lastPid = ParentPid;
                ParentPid = ParentProcessUtil.GetParentProcessId(currentPid);
            }
            return false;
        }

        public static void Kill(int pid, uint exitcode=1, bool dontKillSelf=true) 
        {
            if (dontKillSelf && isCurrentProcessUnderPid(pid)) 
            {
                return;
            }
            uint PROCESS_TERMINATE = 0x0001;
            IntPtr handle= NativeMethods.OpenProcess(PROCESS_TERMINATE, false, (uint)pid);
            if (handle == IntPtr.Zero) 
            {
                return;
            }
            NativeMethods.TerminateProcess(handle, exitcode);
            NativeMethods.CloseHandle(handle);
        }
        public static string GetProcessName(int pid) 
        {
            uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
            IntPtr handle = NativeMethods.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)pid);
            if (handle == IntPtr.Zero)
            {
                return null;
            }
            uint path_length = (uint)short.MaxValue;
            StringBuilder path = new StringBuilder((int)path_length);
            if (!NativeMethods.QueryFullProcessImageName(handle, 0, path, ref path_length))
            {
                return null;
            }
            return Path.GetFileNameWithoutExtension(new FileInfo(path.ToString(0, (int)path_length)).FullName);
        }
    }
}
