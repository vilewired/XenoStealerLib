using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace XenoStealerLib.Utils
{
    public class SpecialNativeMethods
    {
        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtWow64QueryInformationProcess64(
            IntPtr ProcessHandle,
            PROCESSINFOCLASS ProcessInformationClass,
            ref PROCESS_BASIC_INFORMATION64 ProcessInformation,
            int BufferSize,
            ref ulong NumberOfBytesRead);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtWow64ReadVirtualMemory64(
            IntPtr ProcessHandle,
            ulong BaseAddress,
            IntPtr Buffer,
            ulong BufferSize,
            ref ulong NumberOfBytesWritten);
        
        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtWow64WriteVirtualMemory64(
            IntPtr ProcessHandle,
            ulong BaseAddress,
            IntPtr Buffer,
            ulong BufferSize,
            ref ulong NumberOfBytesWritten);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern IntPtr RtlCreateHeap(
            uint Flags,
            IntPtr HeapBase,
            uint ReserveSize,
            uint CommitSize,
            IntPtr Lock,
            IntPtr Parameters);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern IntPtr RtlDestroyHeap(IntPtr HeapHandle);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern IntPtr RtlAllocateHeap(IntPtr HeapHandle, uint Flags, uint Size);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern bool RtlFreeHeap(IntPtr HeapHandle, uint Flags, IntPtr BaseAddress);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern bool RtlCreateUnicodeStringFromAsciiz(
            ref UNICODE_STRING DestinationString,
            
            [MarshalAs(UnmanagedType.LPStr)]
            string SourceString);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern void RtlFreeUnicodeString(ref UNICODE_STRING UnicodeString);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern IntPtr RtlImageNtHeader(IntPtr BaseOfImage);


        public static void RtlInitAnsiString(ref STRING destinationString, string sourceString)
        {
            if (sourceString != null)
            {
                byte[] ansiBytes = Encoding.GetEncoding("Windows-1252").GetBytes(sourceString);
                IntPtr unmanagedBuffer = Marshal.AllocHGlobal(ansiBytes.Length + 1); // +1 for the null terminator
                Marshal.Copy(ansiBytes, 0, unmanagedBuffer, ansiBytes.Length);
                Marshal.WriteByte(unmanagedBuffer + ansiBytes.Length, 0);
                destinationString.Length = (ushort)ansiBytes.Length;
                destinationString.MaximumLength = (ushort)(ansiBytes.Length + 1);  // +1 for the null terminator
                destinationString.Buffer = (uint)unmanagedBuffer; 
            }
            else
            {
                destinationString.Length = 0;
                destinationString.MaximumLength = 0;
                destinationString.Buffer = 0;
            }
        }

        public static void RtlInitAnsiString64(ref STRING64 destinationString, string sourceString)
        {
            if (sourceString != null)
            {
                byte[] ansiBytes = Encoding.GetEncoding("Windows-1252").GetBytes(sourceString);
                IntPtr unmanagedBuffer = Marshal.AllocHGlobal(ansiBytes.Length + 1); // +1 for the null terminator
                Marshal.Copy(ansiBytes, 0, unmanagedBuffer, ansiBytes.Length);
                Marshal.WriteByte(unmanagedBuffer + ansiBytes.Length, 0);
                destinationString.Length = (ushort)ansiBytes.Length;
                destinationString.MaximumLength = (ushort)(ansiBytes.Length + 1);  // +1 for the null terminator
                destinationString.Buffer = (ulong)unmanagedBuffer;
            }
            else
            {
                destinationString.Length = 0;
                destinationString.MaximumLength = 0;
                destinationString.Buffer = 0;
            }
        }

        public static void RtlInitUnicodeString(ref UNICODE_STRING destinationString, string sourceString)
        {
            if (sourceString != null)
            {
                byte[] UnicodeBytes = Encoding.Unicode.GetBytes(sourceString);
                IntPtr unmanagedBuffer = Marshal.AllocHGlobal(UnicodeBytes.Length + 2); // +2 for the unicode null terminator
                Marshal.Copy(UnicodeBytes, 0, unmanagedBuffer, UnicodeBytes.Length);
                Marshal.WriteInt16(unmanagedBuffer + UnicodeBytes.Length, 0);
                destinationString.Length = (ushort)UnicodeBytes.Length;
                destinationString.MaximumLength = (ushort)(UnicodeBytes.Length + 2);  // +2 for the unicode null terminator
                destinationString.Buffer = (uint)unmanagedBuffer;
            }
            else
            {
                destinationString.Length = 0;
                destinationString.MaximumLength = 0;
                destinationString.Buffer = 0;
            }
        }

        public static void RtlInitUnicodeString64(ref UNICODE_STRING64 destinationString, string sourceString)
        {
            if (sourceString != null)
            {
                byte[] UnicodeBytes = Encoding.Unicode.GetBytes(sourceString);
                IntPtr unmanagedBuffer = Marshal.AllocHGlobal(UnicodeBytes.Length + 2); // +2 for the unicode null terminator
                Marshal.Copy(UnicodeBytes, 0, unmanagedBuffer, UnicodeBytes.Length);
                Marshal.WriteInt16(unmanagedBuffer + UnicodeBytes.Length, 0);
                destinationString.Length = (ushort)UnicodeBytes.Length;
                destinationString.MaximumLength = (ushort)(UnicodeBytes.Length + 2);  // +2 for the unicode null terminator
                destinationString.Buffer = (ulong)unmanagedBuffer;
            }
            else
            {
                destinationString.Length = 0;
                destinationString.MaximumLength = 0;
                destinationString.Buffer = 0;
            }
        }

        public static void RtlFreeUnicodeString64(ref UNICODE_STRING64 UnicodeString) 
        {
            if ((UnicodeString.Buffer & ~0xFFFFFFFFUL) != 0) 
            {
                throw new Exception("the buffer is empty!");
            }
            UNICODE_STRING str = new UNICODE_STRING
            {
                Length = UnicodeString.Length,
                MaximumLength = UnicodeString.MaximumLength,
                Buffer = (uint)UnicodeString.Buffer
            };

            RtlFreeUnicodeString(ref str);
        }

        public static bool RtlCreateUnicodeString64FromAsciiz(ref UNICODE_STRING64 DestinationString, string SourceString) 
        {
            UNICODE_STRING str = new UNICODE_STRING();
            bool result = RtlCreateUnicodeStringFromAsciiz(ref str, SourceString);
            DestinationString.Length = str.Length;
            DestinationString.MaximumLength = str.MaximumLength;
            DestinationString.Buffer = str.Buffer;
            return result;
        }


    }
}
