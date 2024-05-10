using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace XenoStealerLib.Utils
{

    public enum PROCESSINFOCLASS
    {
        ProcessBasicInformation, // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
        ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
        ProcessIoCounters, // q: IO_COUNTERS
        ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
        ProcessTimes, // q: KERNEL_USER_TIMES
        ProcessBasePriority, // s: KPRIORITY
        ProcessRaisePriority, // s: ULONG
        ProcessDebugPort, // q: HANDLE
        ProcessExceptionPort, // s: PROCESS_EXCEPTION_PORT
        ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
        ProcessLdtInformation, // qs: PROCESS_LDT_INFORMATION // 10
        ProcessLdtSize, // s: PROCESS_LDT_SIZE
        ProcessDefaultHardErrorMode, // qs: ULONG
        ProcessIoPortHandlers, // (kernel-mode only)
        ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
        ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
        ProcessUserModeIOPL,
        ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
        ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
        ProcessWx86Information,
        ProcessHandleCount, // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
        ProcessAffinityMask, // s: KAFFINITY
        ProcessPriorityBoost, // qs: ULONG
        ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
        ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
        ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
        ProcessWow64Information, // q: ULONG_PTR
        ProcessImageFileName, // q: UNICODE_STRING
        ProcessLUIDDeviceMapsEnabled, // q: ULONG
        ProcessBreakOnTermination, // qs: ULONG
        ProcessDebugObjectHandle, // q: HANDLE // 30
        ProcessDebugFlags, // qs: ULONG
        ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
        ProcessIoPriority, // qs: IO_PRIORITY_HINT
        ProcessExecuteFlags, // qs: ULONG
        ProcessResourceManagement, // ProcessTlsInformation // PROCESS_TLS_INFORMATION
        ProcessCookie, // q: ULONG
        ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
        ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
        ProcessPagePriority, // q: PAGE_PRIORITY_INFORMATION
        ProcessInstrumentationCallback, // qs: PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40
        ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
        ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]
        ProcessImageFileNameWin32, // q: UNICODE_STRING
        ProcessImageFileMapping, // q: HANDLE (input)
        ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
        ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
        ProcessGroupInformation, // q: USHORT[]
        ProcessTokenVirtualizationEnabled, // s: ULONG
        ProcessConsoleHostProcess, // q: ULONG_PTR // ProcessOwnerInformation
        ProcessWindowInformation, // q: PROCESS_WINDOW_INFORMATION // 50
        ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
        ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
        ProcessDynamicFunctionTableInformation,
        ProcessHandleCheckingMode, // qs: ULONG; s: 0 disables, otherwise enables
        ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
        ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
        ProcessWorkingSetControl, // s: PROCESS_WORKING_SET_CONTROL
        ProcessHandleTable, // q: ULONG[] // since WINBLUE
        ProcessCheckStackExtentsMode,
        ProcessCommandLineInformation, // q: UNICODE_STRING // 60
        ProcessProtectionInformation, // q: PS_PROTECTION
        ProcessMemoryExhaustion, // PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
        ProcessFaultInformation, // PROCESS_FAULT_INFORMATION
        ProcessTelemetryIdInformation, // PROCESS_TELEMETRY_ID_INFORMATION
        ProcessCommitReleaseInformation, // PROCESS_COMMIT_RELEASE_INFORMATION
        ProcessDefaultCpuSetsInformation,
        ProcessAllowedCpuSetsInformation,
        ProcessSubsystemProcess,
        ProcessJobMemoryInformation, // PROCESS_JOB_MEMORY_INFO
        ProcessInPrivate, // since THRESHOLD2 // 70
        ProcessRaiseUMExceptionOnInvalidHandleClose, // qs: ULONG; s: 0 disables, otherwise enables
        ProcessIumChallengeResponse,
        ProcessChildProcessInformation, // PROCESS_CHILD_PROCESS_INFORMATION
        ProcessHighGraphicsPriorityInformation,
        ProcessSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
        ProcessEnergyValues, // PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES
        ProcessActivityThrottleState, // PROCESS_ACTIVITY_THROTTLE_STATE
        ProcessActivityThrottlePolicy, // PROCESS_ACTIVITY_THROTTLE_POLICY
        ProcessWin32kSyscallFilterInformation,
        ProcessDisableSystemAllowedCpuSets, // 80
        ProcessWakeInformation, // PROCESS_WAKE_INFORMATION
        ProcessEnergyTrackingState, // PROCESS_ENERGY_TRACKING_STATE
        ProcessManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
        ProcessCaptureTrustletLiveDump,
        ProcessTelemetryCoverage,
        ProcessEnclaveInformation,
        ProcessEnableReadWriteVmLogging, // PROCESS_READWRITEVM_LOGGING_INFORMATION
        ProcessUptimeInformation, // PROCESS_UPTIME_INFORMATION
        ProcessImageSection, // q: HANDLE
        ProcessDebugAuthInformation, // since REDSTONE4 // 90
        ProcessSystemResourceManagement, // PROCESS_SYSTEM_RESOURCE_MANAGEMENT
        ProcessSequenceNumber, // q: ULONGLONG
        ProcessLoaderDetour, // since REDSTONE5
        ProcessSecurityDomainInformation, // PROCESS_SECURITY_DOMAIN_INFORMATION
        ProcessCombineSecurityDomainsInformation, // PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
        ProcessEnableLogging, // PROCESS_LOGGING_INFORMATION
        ProcessLeapSecondInformation, // PROCESS_LEAP_SECOND_INFORMATION
        ProcessFiberShadowStackAllocation, // PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION // since 19H1
        ProcessFreeFiberShadowStackAllocation, // PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
        MaxProcessInfoClass
    };

    public enum SYSTEM_INFORMATION_CLASS
    {
        SystemBasicInformation = 0x00,
        SystemProcessorInformation = 0x01,
        SystemPerformanceInformation = 0x02,
        SystemTimeOfDayInformation = 0x03,
        SystemPathInformation = 0x04,
        SystemProcessInformation = 0x05,
        SystemCallCountInformation = 0x06,
        SystemDeviceInformation = 0x07,
        SystemProcessorPerformanceInformation = 0x08,
        SystemFlagsInformation = 0x09,
        SystemCallTimeInformation = 0x0A,
        SystemModuleInformation = 0x0B,
        SystemLocksInformation = 0x0C,
        SystemStackTraceInformation = 0x0D,
        SystemPagedPoolInformation = 0x0E,
        SystemNonPagedPoolInformation = 0x0F,
        SystemHandleInformation = 0x10,
        SystemObjectInformation = 0x11,
        SystemPageFileInformation = 0x12,
        SystemVdmInstemulInformation = 0x13,
        SystemVdmBopInformation = 0x14,
        SystemFileCacheInformation = 0x15,
        SystemPoolTagInformation = 0x16,
        SystemInterruptInformation = 0x17,
        SystemDpcBehaviorInformation = 0x18,
        SystemFullMemoryInformation = 0x19,
        SystemLoadGdiDriverInformation = 0x1A,
        SystemUnloadGdiDriverInformation = 0x1B,
        SystemTimeAdjustmentInformation = 0x1C,
        SystemSummaryMemoryInformation = 0x1D,
        SystemMirrorMemoryInformation = 0x1E,
        SystemPerformanceTraceInformation = 0x1F,
        SystemObsolete0 = 0x20,
        SystemExceptionInformation = 0x21,
        SystemCrashDumpStateInformation = 0x22,
        SystemKernelDebuggerInformation = 0x23,
        SystemContextSwitchInformation = 0x24,
        SystemRegistryQuotaInformation = 0x25,
        SystemExtendServiceTableInformation = 0x26,
        SystemPrioritySeperation = 0x27,
        SystemVerifierAddDriverInformation = 0x28,
        SystemVerifierRemoveDriverInformation = 0x29,
        SystemProcessorIdleInformation = 0x2A,
        SystemLegacyDriverInformation = 0x2B,
        SystemCurrentTimeZoneInformation = 0x2C,
        SystemLookasideInformation = 0x2D,
        SystemTimeSlipNotification = 0x2E,
        SystemSessionCreate = 0x2F,
        SystemSessionDetach = 0x30,
        SystemSessionInformation = 0x31,
        SystemRangeStartInformation = 0x32,
        SystemVerifierInformation = 0x33,
        SystemVerifierThunkExtend = 0x34,
        SystemSessionProcessInformation = 0x35,
        SystemLoadGdiDriverInSystemSpace = 0x36,
        SystemNumaProcessorMap = 0x37,
        SystemPrefetcherInformation = 0x38,
        SystemExtendedProcessInformation = 0x39,
        SystemRecommendedSharedDataAlignment = 0x3A,
        SystemComPlusPackage = 0x3B,
        SystemNumaAvailableMemory = 0x3C,
        SystemProcessorPowerInformation = 0x3D,
        SystemEmulationBasicInformation = 0x3E,
        SystemEmulationProcessorInformation = 0x3F,
        SystemExtendedHandleInformation = 0x40,
        SystemLostDelayedWriteInformation = 0x41,
        SystemBigPoolInformation = 0x42,
        SystemSessionPoolTagInformation = 0x43,
        SystemSessionMappedViewInformation = 0x44,
        SystemHotpatchInformation = 0x45,
        SystemObjectSecurityMode = 0x46,
        SystemWatchdogTimerHandler = 0x47,
        SystemWatchdogTimerInformation = 0x48,
        SystemLogicalProcessorInformation = 0x49,
        SystemWow64SharedInformationObsolete = 0x4A,
        SystemRegisterFirmwareTableInformationHandler = 0x4B,
        SystemFirmwareTableInformation = 0x4C,
        SystemModuleInformationEx = 0x4D,
        SystemVerifierTriageInformation = 0x4E,
        SystemSuperfetchInformation = 0x4F,
        SystemMemoryListInformation = 0x50,
        SystemFileCacheInformationEx = 0x51,
        SystemThreadPriorityClientIdInformation = 0x52,
        SystemProcessorIdleCycleTimeInformation = 0x53,
        SystemVerifierCancellationInformation = 0x54,
        SystemProcessorPowerInformationEx = 0x55,
        SystemRefTraceInformation = 0x56,
        SystemSpecialPoolInformation = 0x57,
        SystemProcessIdInformation = 0x58,
        SystemErrorPortInformation = 0x59,
        SystemBootEnvironmentInformation = 0x5A,
        SystemHypervisorInformation = 0x5B,
        SystemVerifierInformationEx = 0x5C,
        SystemTimeZoneInformation = 0x5D,
        SystemImageFileExecutionOptionsInformation = 0x5E,
        SystemCoverageInformation = 0x5F,
        SystemPrefetchPatchInformation = 0x60,
        SystemVerifierFaultsInformation = 0x61,
        SystemSystemPartitionInformation = 0x62,
        SystemSystemDiskInformation = 0x63,
        SystemProcessorPerformanceDistribution = 0x64,
        SystemNumaProximityNodeInformation = 0x65,
        SystemDynamicTimeZoneInformation = 0x66,
        SystemCodeIntegrityInformation = 0x67,
        SystemProcessorMicrocodeUpdateInformation = 0x68,
        SystemProcessorBrandString = 0x69,
        SystemVirtualAddressInformation = 0x6A,
        SystemLogicalProcessorAndGroupInformation = 0x6B,
        SystemProcessorCycleTimeInformation = 0x6C,
        SystemStoreInformation = 0x6D,
        SystemRegistryAppendString = 0x6E,
        SystemAitSamplingValue = 0x6F,
        SystemVhdBootInformation = 0x70,
        SystemCpuQuotaInformation = 0x71,
        SystemNativeBasicInformation = 0x72,
        SystemErrorPortTimeouts = 0x73,
        SystemLowPriorityIoInformation = 0x74,
        SystemBootEntropyInformation = 0x75,
        SystemVerifierCountersInformation = 0x76,
        SystemPagedPoolInformationEx = 0x77,
        SystemSystemPtesInformationEx = 0x78,
        SystemNodeDistanceInformation = 0x79,
        SystemAcpiAuditInformation = 0x7A,
        SystemBasicPerformanceInformation = 0x7B,
        SystemQueryPerformanceCounterInformation = 0x7C,
        SystemSessionBigPoolInformation = 0x7D,
        SystemBootGraphicsInformation = 0x7E,
        SystemScrubPhysicalMemoryInformation = 0x7F,
        SystemBadPageInformation = 0x80,
        SystemProcessorProfileControlArea = 0x81,
        SystemCombinePhysicalMemoryInformation = 0x82,
        SystemEntropyInterruptTimingInformation = 0x83,
        SystemConsoleInformation = 0x84,
        SystemPlatformBinaryInformation = 0x85,
        SystemPolicyInformation = 0x86,
        SystemHypervisorProcessorCountInformation = 0x87,
        SystemDeviceDataInformation = 0x88,
        SystemDeviceDataEnumerationInformation = 0x89,
        SystemMemoryTopologyInformation = 0x8A,
        SystemMemoryChannelInformation = 0x8B,
        SystemBootLogoInformation = 0x8C,
        SystemProcessorPerformanceInformationEx = 0x8D,
        SystemCriticalProcessErrorLogInformation = 0x8E,
        SystemSecureBootPolicyInformation = 0x8F,
        SystemPageFileInformationEx = 0x90,
        SystemSecureBootInformation = 0x91,
        SystemEntropyInterruptTimingRawInformation = 0x92,
        SystemPortableWorkspaceEfiLauncherInformation = 0x93,
        SystemFullProcessInformation = 0x94,
        SystemKernelDebuggerInformationEx = 0x95,
        SystemBootMetadataInformation = 0x96,
        SystemSoftRebootInformation = 0x97,
        SystemElamCertificateInformation = 0x98,
        SystemOfflineDumpConfigInformation = 0x99,
        SystemProcessorFeaturesInformation = 0x9A,
        SystemRegistryReconciliationInformation = 0x9B,
        SystemEdidInformation = 0x9C,
        SystemManufacturingInformation = 0x9D,
        SystemEnergyEstimationConfigInformation = 0x9E,
        SystemHypervisorDetailInformation = 0x9F,
        SystemProcessorCycleStatsInformation = 0xA0,
        SystemVmGenerationCountInformation = 0xA1,
        SystemTrustedPlatformModuleInformation = 0xA2,
        SystemKernelDebuggerFlags = 0xA3,
        SystemCodeIntegrityPolicyInformation = 0xA4,
        SystemIsolatedUserModeInformation = 0xA5,
        SystemHardwareSecurityTestInterfaceResultsInformation = 0xA6,
        SystemSingleModuleInformation = 0xA7,
        SystemAllowedCpuSetsInformation = 0xA8,
        SystemDmaProtectionInformation = 0xA9,
        SystemInterruptCpuSetsInformation = 0xAA,
        SystemSecureBootPolicyFullInformation = 0xAB,
        SystemCodeIntegrityPolicyFullInformation = 0xAC,
        SystemAffinitizedInterruptProcessorInformation = 0xAD,
        SystemRootSiloInformation = 0xAE,
        SystemCpuSetInformation = 0xAF,
        SystemCpuSetTagInformation = 0xB0,
        SystemWin32WerStartCallout = 0xB1,
        SystemSecureKernelProfileInformation = 0xB2,
        SystemCodeIntegrityPlatformManifestInformation = 0xB3,
        SystemInterruptSteeringInformation = 0xB4,
        SystemSuppportedProcessorArchitectures = 0xB5,
        SystemMemoryUsageInformation = 0xB6,
        SystemCodeIntegrityCertificateInformation = 0xB7,
        SystemPhysicalMemoryInformation = 0xB8,
        SystemControlFlowTransition = 0xB9,
        SystemKernelDebuggingAllowed = 0xBA,
        SystemActivityModerationExeState = 0xBB,
        SystemActivityModerationUserSettings = 0xBC,
        SystemCodeIntegrityPoliciesFullInformation = 0xBD,
        SystemCodeIntegrityUnlockInformation = 0xBE,
        SystemIntegrityQuotaInformation = 0xBF,
        SystemFlushInformation = 0xC0,
        SystemProcessorIdleMaskInformation = 0xC1,
        SystemSecureDumpEncryptionInformation = 0xC2,
        SystemWriteConstraintInformation = 0xC3,
        SystemKernelVaShadowInformation = 0xC4,
        SystemHypervisorSharedPageInformation = 0xC5,
        SystemFirmwareBootPerformanceInformation = 0xC6,
        SystemCodeIntegrityVerificationInformation = 0xC7,
        SystemFirmwarePartitionInformation = 0xC8,
        SystemSpeculationControlInformation = 0xC9,
        SystemDmaGuardPolicyInformation = 0xCA,
        SystemEnclaveLaunchControlInformation = 0xCB,
        SystemWorkloadAllowedCpuSetsInformation = 0xCC,
        SystemCodeIntegrityUnlockModeInformation = 0xCD,
        SystemLeapSecondInformation = 0xCE,
        SystemFlags2Information = 0xCF,
        SystemSecurityModelInformation = 0xD0,
        SystemCodeIntegritySyntheticCacheInformation = 0xD1,
        MaxSystemInfoClass = 0xD2
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_HANDLE_TABLE_ENTRY_INFO
    {
        public ushort UniqueProcessId;
        public ushort CreatorBackTraceIndex;
        public byte ObjectTypeIndex;
        public byte HandleAttributes;
        public ushort HandleValue;
        public IntPtr pAddress;
        public uint dwGrantedAccess;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_HANDLE_INFORMATION
    {
        public uint NumberOfHandles;
        public IntPtr Handles;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct STRING 
    {
        public ushort Length;
        public ushort MaximumLength;
        public uint Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]

    public struct STRING64
    {
        public ushort Length;
        public ushort MaximumLength;
        public ulong Buffer;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public uint Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]

    public struct UNICODE_STRING64
    {
        public ushort Length;
        public ushort MaximumLength;
        public ulong Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]

    public struct LIST_ENTRY64
    {
        public ulong Flink;
        public ulong Blink;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PEB_LDR_DATA64 
    {
        public uint Length;
        public bool Initialized;
        public ulong SsHandle;
        public LIST_ENTRY64 InLoadOrderModuleList;
        public LIST_ENTRY64 InMemoryOrderModuleList;
        public LIST_ENTRY64 InInitializationOrderModuleList;
        public ulong EntryInProgress;
        public bool ShutdownInProgress;
        public ulong ShutdownThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LDR_DATA_TABLE_ENTRY64_SNAP 
    {
        public LIST_ENTRY64 InLoadOrderLinks;
        public LIST_ENTRY64 InMemoryOrderLinks;
        public LIST_ENTRY64 InInitializationOrderLinks;
        public ulong DllBase;
        public ulong EntryPoint;
        public uint SizeOfImage;
        public UNICODE_STRING64 FullDllName;
        public UNICODE_STRING64 BaseDllName;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_BASIC_INFORMATION64 
    {
        public int ExitStatus;
        public ulong PebBaseAddress;
        public ulong AffinityMask;
        public uint BasePriority;
        public ulong UniqueProcessId;
        public ulong InheritedFromUniqueProcessId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct _RTL_DRIVE_LETTER_CURDIR
    {
        public ushort Flags;
        public ushort Length;
        public int TimeStamp;
        public STRING64 DosPath;
    };

    [StructLayout(LayoutKind.Sequential)]
    public struct _CURDIR
    {
        public UNICODE_STRING64 DosPath;
        public ulong Handle;
    };

    [StructLayout(LayoutKind.Sequential)]
    public struct RTL_USER_PROCESS_PARAMETERS64
    {
        public uint MaximumLength;
        public uint Length;
        public uint Flags;
        public uint DebugFlags;
        public ulong ConsoleHandle;
        public uint ConsoleFlags;
        public ulong StandardInput;
        public ulong StandardOutput;
        public ulong StandardError;
        public _CURDIR CurrentDirectory;
        public UNICODE_STRING64 DllPath;
        public UNICODE_STRING64 ImagePathName;
        public UNICODE_STRING64 CommandLine;
        public ulong Environment;
        public uint StartingX;
        public uint StartingY;
        public uint CountX;
        public uint CountY;
        public uint CountCharsX;
        public uint CountCharsY;
        public uint FillAttribute;
        public uint WindowFlags;
        public uint ShowWindowFlags;
        public UNICODE_STRING64 WindowTitle;
        public UNICODE_STRING64 DesktopInfo;
        public UNICODE_STRING64 ShellInfo;
        public UNICODE_STRING64 RuntimeData;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public _RTL_DRIVE_LETTER_CURDIR[] CurrentDirectores;
        public ulong EnvironmentSize;
        public ulong EnvironmentVersion;
        public ulong PackageDependencyData;
        public uint ProcessGroupId;
        public uint LoaderThreads;
        public UNICODE_STRING64 RedirectionDllName;
        public UNICODE_STRING64 HeapPartitionName;
        public ulong DefaultThreadpoolCpuSetMasks;
        public uint DefaultThreadpoolCpuSetMaskCount;
        public uint DefaultThreadpoolThreadMaximum;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_FILE_HEADER 
    {
        public ushort Machine;
        public ushort NumberOfSections;
        public uint TimeDateStamp;
        public uint PointerToSymbolTable;
        public uint NumberOfSymbols;
        public ushort SizeOfOptionalHeader;
        public ushort Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DATA_DIRECTORY 
    {
        public uint VirtualAddress;
        public uint Size;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_OPTIONAL_HEADER32
    {
        public ushort Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public uint BaseOfData;
         
        public uint ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public ushort DllCharacteristics;
        public uint SizeOfStackReserve;
        public uint SizeOfStackCommit;
        public uint SizeOfHeapReserve;
        public uint SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public IMAGE_DATA_DIRECTORY[] DataDirectory;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_OPTIONAL_HEADER64
    {
        public ushort Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;

        public ulong ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public ushort DllCharacteristics;
        public ulong SizeOfStackReserve;
        public ulong SizeOfStackCommit;
        public ulong SizeOfHeapReserve;
        public ulong SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public IMAGE_DATA_DIRECTORY[] DataDirectory;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_NT_HEADERS32
    {
        public uint Signature;
        public IMAGE_FILE_HEADER FileHeader;
        public IMAGE_OPTIONAL_HEADER32 OptionalHeader;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_NT_HEADERS64
    {
        public uint Signature;
        public IMAGE_FILE_HEADER FileHeader;
        public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DOS_HEADER 
    {
        public ushort e_magic;                   
        public ushort e_cblp;                    
        public ushort e_cp;                       
        public ushort e_crlc;                   
        public ushort e_cparhdr;               
        public ushort e_minalloc;               
        public ushort e_maxalloc;           
        public ushort e_ss;                       
        public ushort e_sp;                  
        public ushort e_csum;                    
        public ushort e_ip;                  
        public ushort e_cs;               
        public ushort e_lfarlc;         
        public ushort e_ovno;      
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public ushort[] e_res;                
        public ushort e_oemid;                 
        public ushort e_oeminfo;                   
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
        public ushort[] e_res2;                  
        public int e_lfanew;                    
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_EXPORT_DIRECTORY
    {
        public uint Characteristics;
        public uint TimeDateStamp;
        public ushort MajorVersion;
        public ushort MinorVersion;
        public uint Name;
        public uint Base;
        public uint NumberOfFunctions;
        public uint NumberOfNames;
        public uint AddressOfFunctions;     // RVA from base of image
        public uint AddressOfNames;         // RVA from base of image
        public uint AddressOfNameOrdinals;  // RVA from base of image
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct UlongResult
    {
        public ulong Value;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct UintResult
    {
        public uint Value;
    }

    public enum RM_APP_TYPE
    {
        RmUnknownApp = 0,
        RmMainWindow = 1,
        RmOtherWindow = 2,
        RmService = 3,
        RmExplorer = 4,
        RmConsole = 5,
        RmCritical = 1000
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct RM_PROCESS_INFO
    {
        public RM_UNIQUE_PROCESS Process;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = NativeMethods.CCH_RM_MAX_APP_NAME + 1)] public string strAppName;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = NativeMethods.CCH_RM_MAX_SVC_NAME + 1)] public string strServiceShortName;

        public RM_APP_TYPE ApplicationType;
        public uint AppStatus;
        public uint TSSessionId;
        [MarshalAs(UnmanagedType.Bool)] public bool bRestartable;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct RM_UNIQUE_PROCESS
    {
        public int dwProcessId;
        public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ParentProcessUtilities
    {
        internal IntPtr Reserved1;
        internal IntPtr PebBaseAddress;
        internal IntPtr Reserved2_0;
        internal IntPtr Reserved2_1;
        internal IntPtr UniqueProcessId;
        internal IntPtr InheritedFromUniqueProcessId;
    }

    public enum FileType
    {
        FILE_TYPE_UNKNOWN = 0x0000, // The specified file type is unknown.
        FILE_TYPE_DISK = 0x0001, // The specified file is a disk file.
        FILE_TYPE_CHAR = 0x0002, // The specified file is a character file, typically an LPT device or a console.
        FILE_TYPE_PIPE = 0x0003, // The specified file is a socket, a named pipe, or an anonymous pipe.
        FILE_TYPE_REMOTE = 0x8000, // Unused.
    }

    public static class publicMethods 
    {
        public static ulong GetLdr64(ulong addr)
        {
            return addr + 0x18;
        }

        public static ulong GetProcessParameters64(ulong addr)
        {
            return addr + 0x20;
        }

    }

}
