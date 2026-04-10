#pragma once

#define WINSYS_DEVICE 0x8088
#define KWINSYS_DEVNAME L"\\\\.\\KWinSys"
#define KWINSYS_PROTOCOL_VERSION 0x0103

#define IOCTL_WINSYS_GET_VERSION				CTL_CODE(WINSYS_DEVICE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINSYS_LIST_CALLBACKS 			CTL_CODE(WINSYS_DEVICE, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINSYS_LIST_SSDT		 			CTL_CODE(WINSYS_DEVICE, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINSYS_LIST_MODULES	 			CTL_CODE(WINSYS_DEVICE, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINSYS_CREATE_MODULE_SNAPSHOT		CTL_CODE(WINSYS_DEVICE, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINSYS_QUERY_MODULE_PAGE			CTL_CODE(WINSYS_DEVICE, 0x80B, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINSYS_RELEASE_MODULE_SNAPSHOT	CTL_CODE(WINSYS_DEVICE, 0x80C, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINSYS_ENUM_PROCESS_OBJECTS		CTL_CODE(WINSYS_DEVICE, 0x80D, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINSYS_SET_EPROCESS_OFFSETS		CTL_CODE(WINSYS_DEVICE, 0x80E, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINSYS_CROSS_CHECK_PROCESSES		CTL_CODE(WINSYS_DEVICE, 0x80F, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINSYS_QUERY_GDT					CTL_CODE(WINSYS_DEVICE, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINSYS_QUERY_IDT					CTL_CODE(WINSYS_DEVICE, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_WINSYS_QUERY_IRP_DISPATCH			CTL_CODE(WINSYS_DEVICE, 0x814, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINSYS_QUERY_OBJECT_PROCS			CTL_CODE(WINSYS_DEVICE, 0x815, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINSYS_ENUM_IO_TIMERS				CTL_CODE(WINSYS_DEVICE, 0x816, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINSYS_ENUM_WFP_FILTERS			CTL_CODE(WINSYS_DEVICE, 0x817, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINSYS_ENUM_WFP_CALLOUTS			CTL_CODE(WINSYS_DEVICE, 0x818, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* ---- New IOCTLs for roadmap features ---- */
#define IOCTL_WINSYS_QUERY_INSTRUMENTATION_CB	CTL_CODE(WINSYS_DEVICE, 0x819, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINSYS_SNAPSHOT_CALLBACKS			CTL_CODE(WINSYS_DEVICE, 0x81A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINSYS_DIFF_CALLBACKS				CTL_CODE(WINSYS_DEVICE, 0x81B, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINSYS_ENUM_APC					CTL_CODE(WINSYS_DEVICE, 0x81C, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINSYS_QUERY_DSE_STATUS			CTL_CODE(WINSYS_DEVICE, 0x81D, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINSYS_QUERY_KERNEL_INTEGRITY		CTL_CODE(WINSYS_DEVICE, 0x81E, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINSYS_QUERY_PATCHGUARD_TIMERS	CTL_CODE(WINSYS_DEVICE, 0x81F, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINSYS_MEMORY_READ				CTL_CODE(WINSYS_DEVICE, 0x820, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINSYS_MEMORY_WRITE				CTL_CODE(WINSYS_DEVICE, 0x821, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINSYS_QUERY_KERNEL_LOGS			CTL_CODE(WINSYS_DEVICE, 0x825, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MAX_KERNEL_PROCESSES 1024
#define MAX_CROSS_CHECK_PROCESSES 2048

/* Cross-check source flags */
#define PROCESS_SOURCE_ACTIVE_LINKS  0x01
#define PROCESS_SOURCE_CID_TABLE     0x02

#define OB_OPERATION_HANDLE_CREATE              0x00000001
#define OB_OPERATION_HANDLE_DUPLICATE           0x00000002

#pragma pack(push, 1)

//struct OpenObjectByAddressData {
//	void* Address;
//	ACCESS_MASK Access;
//};
//
//struct OpenObjectByNameData {
//	ACCESS_MASK Access;
//	USHORT TypeIndex;
//	WCHAR Name[1];
//};
//
//struct DupHandleData {
//	ULONG SourceHandle;
//	ULONG SourcePid;
//	ACCESS_MASK AccessMask;
//	ULONG Flags;
//};
//
//struct OpenProcessThreadData {
//	ULONG Id;
//	ACCESS_MASK AccessMask;
//};

typedef struct {
	unsigned long long addr;
	char name[150];
	int type;
	unsigned long operations;
} MODULE_INFO;

typedef struct {
	unsigned long long ProcessNotifyArray;
	unsigned long long ThreadNotifyArray;
	unsigned long long ImageNotifyArray;
	unsigned long long RegistryCallbackListHead;
	unsigned long ObjectTypeCallbackListOffset;
} CALLBACK_QUERY;

typedef struct {
	unsigned long long ImageBase;
	unsigned long ImageSize;
	unsigned short LoadOrderIndex;
	unsigned short InitOrderIndex;
	unsigned short LoadCount;
	unsigned long Flags;
	char Name[128];
	char FullPath[260];
} KERNEL_MODULE_ENTRY;

typedef struct {
	unsigned long Count;
} MODULE_SNAPSHOT_INFO;

typedef struct {
	unsigned long StartIndex;
	unsigned long Count;
} MODULE_PAGE_REQUEST;

typedef struct
{
	unsigned long* pServiceTable;
	void* pCounterTable;
	unsigned long long NumberOfServices;
	unsigned char* pArgumentTable;
} SSDTStruct;


typedef struct {
	unsigned long ProtectionOffset;
	unsigned long TokenOffset;
	unsigned long PebOffset;
	unsigned long DirectoryTableBaseOffset;
	unsigned long FlagsOffset;
	unsigned long Flags2Offset;
	unsigned long SignatureLevelOffset;
	unsigned long SectionSignatureLevelOffset;
	unsigned long ObjectTableOffset;
	unsigned long MitigationFlagsOffset;
	unsigned long MitigationFlags2Offset;
	unsigned long ActiveProcessLinksOffset;
	unsigned long UniqueProcessIdOffset;
	unsigned long Valid;
} EPROCESS_OFFSETS;

typedef struct {
	unsigned long long EprocessAddress;
	unsigned long ProcessId;
	unsigned long ParentProcessId;
	unsigned long SessionId;
	unsigned long HandleCount;
	unsigned long ThreadCount;
	long long CreateTime;
	char ImageName[16];
	unsigned char Protection;
	unsigned char IsWow64;
	unsigned char IsProtected;
	unsigned char IsProtectedLight;
	/* PDB-resolved fields */
	unsigned long long TokenAddress;
	unsigned long long PebAddress;
	unsigned long long DirectoryTableBase;
	unsigned long long ObjectTableAddress;
	unsigned long Flags;
	unsigned long Flags2;
	unsigned char SignatureLevel;
	unsigned char SectionSignatureLevel;
	unsigned char ProtectionType;
	unsigned char ProtectionSigner;
	unsigned long MitigationFlags;
	unsigned long MitigationFlags2;
} KERNEL_PROCESS_ENTRY;

typedef struct {
	unsigned long ProcessId;
	unsigned long long EprocessAddress;
	char ImageName[16];
	unsigned char Sources;       /* bitmask of PROCESS_SOURCE_* */
	unsigned char _padding[3];
} CROSS_CHECK_PROCESS_ENTRY;

typedef struct {
	unsigned long ActiveLinksCount;
	unsigned long CidTableCount;
	unsigned long TotalEntries;
	unsigned long SuspiciousCount;
	/* followed by TotalEntries * CROSS_CHECK_PROCESS_ENTRY */
} CROSS_CHECK_RESULT;

/* ---- GDT ---- */
typedef struct {
	unsigned short Limit;
	unsigned long long Base;
	unsigned long EntryCount;
	unsigned long long Entries[256];
} GDT_INFO;

/* ---- IDT ---- */
typedef struct {
	unsigned long long IsrAddress;
	unsigned short Segment;
	unsigned char IST;
	unsigned char Type;
	unsigned char DPL;
	unsigned char Present;
	unsigned char _pad[2];
} IDT_ENTRY;

typedef struct {
	unsigned short Limit;
	unsigned long long Base;
	unsigned long EntryCount;
	IDT_ENTRY Entries[256];
} IDT_INFO;


/* ---- IRP Dispatch ---- */
#define IRP_MJ_MAXIMUM_FUNCTION_COUNT 28

typedef struct {
	wchar_t DriverName[256];
} IRP_DISPATCH_REQUEST;

typedef struct {
	unsigned long long HandlerAddress;
} IRP_DISPATCH_ENTRY;

typedef struct {
	unsigned long Count;
	unsigned long long DriverObjectAddress;
	IRP_DISPATCH_ENTRY Entries[IRP_MJ_MAXIMUM_FUNCTION_COUNT];
} IRP_DISPATCH_RESULT;

/* ---- Object Type Procedures ---- */
#define MAX_OBJECT_TYPES 64

typedef struct {
	unsigned long TypeInfoOffset;       /* _OBJECT_TYPE.TypeInfo offset from PDB */
	unsigned long OpenProcOffset;       /* within OBJECT_TYPE_INITIALIZER */
	unsigned long CloseProcOffset;
	unsigned long DeleteProcOffset;
	unsigned long ParseProcOffset;
	unsigned long SecurityProcOffset;
	unsigned long QueryNameProcOffset;
	unsigned long OkayToCloseProcOffset;
	unsigned long Valid;
} OBJECT_PROC_OFFSETS;

typedef struct {
	wchar_t TypeName[64];
	unsigned long TypeIndex;
	unsigned long long TypeObjectAddress;
	unsigned long long OpenProc;
	unsigned long long CloseProc;
	unsigned long long DeleteProc;
	unsigned long long ParseProc;
	unsigned long long SecurityProc;
	unsigned long long QueryNameProc;
	unsigned long long OkayToCloseProc;
} OBJECT_TYPE_PROC_ENTRY;

typedef struct {
	unsigned long Count;
} OBJECT_TYPE_PROC_RESULT;

/* ---- IO Timers ---- */
#define MAX_IO_TIMERS 256

typedef struct {
	unsigned long long IopTimerQueueHead;   /* resolved from PDB */
	unsigned long TimerListOffset;          /* offset within IO_TIMER to linked list entry */
	unsigned long DeviceObjectOffset;       /* offset within IO_TIMER to DeviceObject */
	unsigned long TimerRoutineOffset;       /* offset within IO_TIMER to TimerRoutine */
	unsigned long Valid;
} IO_TIMER_QUERY;

typedef struct {
	unsigned long long DeviceObject;
	unsigned long long TimerRoutine;
	unsigned long long DriverObject;
	char DriverName[128];
} IO_TIMER_ENTRY;

typedef struct {
	unsigned long Count;
} IO_TIMER_RESULT;

/* ---- WFP Filters ---- */
#define MAX_WFP_FILTERS 512

typedef struct {
	unsigned long long FilterId;
	unsigned long ActionType;
	unsigned long Flags;
	wchar_t DisplayName[128];
	char LayerName[64];
	char ProviderName[64];
} WFP_FILTER_ENTRY;

typedef struct {
	unsigned long Count;
} WFP_FILTER_RESULT;

/* ---- WFP Callouts ---- */
#define MAX_WFP_CALLOUTS 512

typedef struct {
	unsigned long CalloutId;
	unsigned long Flags;
	unsigned long long ClassifyFunction;
	unsigned long long NotifyFunction;
	unsigned long long FlowDeleteFunction;
	wchar_t DisplayName[128];
	char LayerName[64];
	char ProviderName[64];
} WFP_CALLOUT_ENTRY;

typedef struct {
	unsigned long Count;
} WFP_CALLOUT_RESULT;

/* ---- Instrumentation Callback Detection ---- */
#define MAX_INSTRUMENTATION_CB_ENTRIES 256

typedef struct {
	unsigned long ProcessId;
	unsigned long long InstrumentationCallback;
	char ImageName[16];
} INSTRUMENTATION_CB_ENTRY;

typedef struct {
	unsigned long Count;
} INSTRUMENTATION_CB_RESULT;

/* ---- Callback Snapshot / Diff ---- */
#define MAX_CALLBACK_SNAPSHOT_ENTRIES 200

typedef struct {
	unsigned long SnapshotId;       /* 0 = take new snapshot, nonzero = diff against this */
} CALLBACK_SNAPSHOT_REQUEST;

typedef struct {
	unsigned long SnapshotId;
	unsigned long EntryCount;
} CALLBACK_SNAPSHOT_RESULT;

typedef struct {
	unsigned long long Address;
	char DriverName[128];
	int Type;                       /* same as MODULE_INFO.type */
	unsigned char ChangeType;       /* 0 = unchanged, 1 = added, 2 = removed */
} CALLBACK_DIFF_ENTRY;

/* ---- APC Queue Viewer ---- */
#define MAX_APC_ENTRIES 512

typedef struct {
	unsigned long ProcessId;
	unsigned long ThreadId;
} APC_QUERY;

typedef struct {
	unsigned long ThreadId;
	unsigned long ProcessId;
	unsigned long long KernelRoutine;
	unsigned long long RundownRoutine;
	unsigned long long NormalRoutine;
	unsigned char ApcMode;          /* 0 = kernel, 1 = user */
	unsigned char Inserted;
	char OwnerDriver[128];
} APC_ENTRY;

typedef struct {
	unsigned long Count;
} APC_RESULT;

/* ---- DSE Status ---- */
typedef struct {
	unsigned long long CiAddress;           /* Address of CI.dll in kernel */
	unsigned long long gCiOptionsAddress;   /* Address of g_CiOptions */
	unsigned long gCiOptionsValue;          /* Current value of g_CiOptions */
	unsigned char DseEnabled;               /* Is DSE enabled */
	unsigned char TestSigningEnabled;       /* Is test signing on */
	unsigned char SecureBootEnabled;        /* Is secure boot active */
	unsigned char HvciEnabled;              /* Is HVCI active */
} DSE_STATUS_INFO;

/* ---- Kernel Integrity Check ---- */
#define MAX_KERNEL_INTEGRITY_ENTRIES 64

typedef struct {
	unsigned long long FunctionAddress;
	unsigned long long ExpectedFirstBytes;  /* first 8 bytes from disk image */
	unsigned long long ActualFirstBytes;    /* first 8 bytes from memory */
	char FunctionName[64];
	unsigned char IsPatched;
} KERNEL_INTEGRITY_ENTRY;

typedef struct {
	unsigned long Count;
	unsigned long PatchedCount;
} KERNEL_INTEGRITY_RESULT;

/* ---- PatchGuard Timer Detection ---- */
#define MAX_PATCHGUARD_ENTRIES 64

typedef struct {
	unsigned long long TimerAddress;
	unsigned long long DpcRoutine;
	unsigned long long DeferredContext;
	unsigned long Period;
	char OwnerModule[128];
	unsigned char IsSuspicious;
} PATCHGUARD_TIMER_ENTRY;

typedef struct {
	unsigned long Count;
	unsigned long SuspiciousCount;
} PATCHGUARD_TIMER_RESULT;

/* ---- Kernel Memory Read / Write ---- */
typedef struct {
	unsigned long Pid;
	unsigned long long Address;
	unsigned long Size;
} MEMORY_READ_REQUEST;

typedef struct {
	unsigned long BytesRead;
	unsigned char Data[4096];
} MEMORY_READ_RESULT;

typedef struct {
	unsigned long Pid;
	unsigned long long Address;
	unsigned long Size;
	unsigned char Data[4096];
} MEMORY_WRITE_REQUEST;

typedef struct {
	unsigned long BytesWritten;
} MEMORY_WRITE_RESULT;


/* ---- Kernel Log Stream ---- */
#define MAX_KERNEL_LOG_ENTRIES 64

typedef struct {
	unsigned long StartSequence;
} KERNEL_LOG_QUERY;

typedef struct {
	unsigned long Sequence;
	char Text[256];
} KERNEL_LOG_ENTRY;

typedef struct {
	unsigned long Count;
	unsigned long NextSequence;
} KERNEL_LOG_RESULT;

#pragma pack(pop)
