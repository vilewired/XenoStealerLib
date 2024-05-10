using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace XenoStealerLib.Utils
{
    class ParentProcessUtil//thx to https://stackoverflow.com/questions/394816/how-to-get-parent-process-in-net-in-managed-way
    {
        private static uint PROCESS_QUERY_INFORMATION = 0x0400;
        public static Process GetParentProcess(int id)
        {
            IntPtr handle = NativeMethods.OpenProcess(PROCESS_QUERY_INFORMATION, false, (uint)id);
            if (handle == IntPtr.Zero)
            {
                return null;
            }
            try
            {
                int parent = GetParentProcess(handle);
                NativeMethods.CloseHandle(handle);
                return Process.GetProcessById(parent);
            }
            catch 
            {
                NativeMethods.CloseHandle(handle);
                return null;
            }
        }

        public static int GetParentProcessId(int id)
        {
            IntPtr handle=NativeMethods.OpenProcess(PROCESS_QUERY_INFORMATION, false, (uint)id);
            if (handle == IntPtr.Zero) 
            {
                return 0;
            }
            try
            {
                int parentPid = GetParentProcess(handle);
                NativeMethods.CloseHandle(handle);
                return parentPid;
            }
            catch 
            {
                NativeMethods.CloseHandle(handle);
                return 0;
            }
        }

        public static int GetParentProcess(IntPtr handle)
        {
            ParentProcessUtilities pbi = new ParentProcessUtilities();
            int returnLength;
            int status = NativeMethods.NtQueryInformationProcess(handle, 0, ref pbi, Marshal.SizeOf(pbi), out returnLength);
            if (status != 0)
                throw new Win32Exception(status);
            return pbi.InheritedFromUniqueProcessId.ToInt32();
        }

    }
}
