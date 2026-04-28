#pragma once

#include <stdint.h>

#define WINSYS_DEFAULT_PORT     50002
#define WINSYS_PROTOCOL_VERSION_NET 0x0002

// Message types: requests 0x1xx, responses 0x2xx
#define MSG_REQ_PING                0x100
#define MSG_RESP_PING               0x200

#define MSG_REQ_PROCESSES           0x101
#define MSG_RESP_PROCESSES          0x201

#define MSG_REQ_SERVICES            0x102
#define MSG_RESP_SERVICES           0x202

#define MSG_REQ_CONNECTIONS         0x103
#define MSG_RESP_CONNECTIONS        0x203

#define MSG_REQ_CALLBACKS           0x104
#define MSG_RESP_CALLBACKS          0x204

#define MSG_REQ_SSDT                0x105
#define MSG_RESP_SSDT               0x205

#define MSG_REQ_KERNEL_MODULES      0x106
#define MSG_RESP_KERNEL_MODULES     0x206

#define MSG_REQ_PROCESS_OBJECTS     0x107
#define MSG_RESP_PROCESS_OBJECTS    0x207

#define MSG_REQ_DRIVER_VERSION      0x108
#define MSG_RESP_DRIVER_VERSION     0x208

#define MSG_REQ_MODULE_PAGES        0x109
#define MSG_RESP_MODULE_PAGES       0x209

#define MSG_REQ_MODULE_SNAPSHOT     0x10A
#define MSG_RESP_MODULE_SNAPSHOT    0x20A

#define MSG_REQ_RELEASE_SNAPSHOT    0x10B
#define MSG_RESP_RELEASE_SNAPSHOT   0x20B

#define MSG_REQ_EPROCESS_OFFSETS    0x10C
#define MSG_RESP_EPROCESS_OFFSETS   0x20C

#define MSG_REQ_SYSINFO             0x10D
#define MSG_RESP_SYSINFO            0x20D

#define MSG_REQ_CROSS_CHECK         0x10E
#define MSG_RESP_CROSS_CHECK        0x20E

#define MSG_REQ_KERNEL_BASE         0x10F
#define MSG_RESP_KERNEL_BASE        0x20F

#define MSG_REQ_PERFORMANCE         0x110
#define MSG_RESP_PERFORMANCE        0x210

#define MSG_REQ_REGISTRY_ENUM       0x111
#define MSG_RESP_REGISTRY_ENUM      0x211

// Driver-based kernel queries
#define MSG_REQ_GDT                 0x112
#define MSG_RESP_GDT                0x212

#define MSG_REQ_IDT                 0x113
#define MSG_RESP_IDT                0x213

#define MSG_REQ_WFP_FILTERS         0x114
#define MSG_RESP_WFP_FILTERS        0x214

#define MSG_REQ_WFP_CALLOUTS        0x115
#define MSG_RESP_WFP_CALLOUTS       0x215

// 0x116 reserved (Object Procedures removed)

#define MSG_REQ_IRP_DISPATCH        0x117
#define MSG_RESP_IRP_DISPATCH       0x217

// NtQuerySystemInformation-based queries
#define MSG_REQ_HANDLES             0x118
#define MSG_RESP_HANDLES            0x218

#define MSG_REQ_BIG_POOL            0x119
#define MSG_RESP_BIG_POOL           0x219

#define MSG_REQ_POOL_TAGS           0x11A
#define MSG_RESP_POOL_TAGS          0x21A

#define MSG_REQ_INTERRUPT_INFO      0x11B
#define MSG_RESP_INTERRUPT_INFO     0x21B

// User-mode system queries
#define MSG_REQ_ETW_SESSIONS        0x11C
#define MSG_RESP_ETW_SESSIONS       0x21C

#define MSG_REQ_ETW_PROVIDERS       0x11D
#define MSG_RESP_ETW_PROVIDERS      0x21D

#define MSG_REQ_CERTIFICATES        0x11E
#define MSG_RESP_CERTIFICATES       0x21E

#define MSG_REQ_ADAPTERS            0x11F
#define MSG_RESP_ADAPTERS           0x21F

#define MSG_REQ_RPC_ENDPOINTS       0x120
#define MSG_RESP_RPC_ENDPOINTS      0x220

#define MSG_REQ_NAMED_PIPES         0x121
#define MSG_RESP_NAMED_PIPES        0x221

#define MSG_REQ_MINIFILTERS         0x122
#define MSG_RESP_MINIFILTERS        0x222

#define MSG_REQ_FILTER_INSTANCES    0x123
#define MSG_RESP_FILTER_INSTANCES   0x223

#define MSG_REQ_OBJ_DIRECTORY       0x124
#define MSG_RESP_OBJ_DIRECTORY      0x224

#define MSG_REQ_NTDLL_FUNCTIONS     0x125
#define MSG_RESP_NTDLL_FUNCTIONS    0x225

// Security / EDR inspection
#define MSG_REQ_INSTRUMENTATION_CB  0x126
#define MSG_RESP_INSTRUMENTATION_CB 0x226

#define MSG_REQ_DSE_STATUS          0x127
#define MSG_RESP_DSE_STATUS         0x227

#define MSG_REQ_KERNEL_INTEGRITY    0x128
#define MSG_RESP_KERNEL_INTEGRITY   0x228

#define MSG_REQ_BYOVD_SCAN         0x129
#define MSG_RESP_BYOVD_SCAN        0x229

// Memory read/write
#define MSG_REQ_MEMORY_READ         0x12A
#define MSG_RESP_MEMORY_READ        0x22A

#define MSG_REQ_MEMORY_WRITE        0x12B
#define MSG_RESP_MEMORY_WRITE       0x22B

// CI Policy
#define MSG_REQ_CI_POLICY           0x12C
#define MSG_RESP_CI_POLICY          0x22C

// Hypervisor hook detection
#define MSG_REQ_HYPERVISOR_HOOKS    0x12D
#define MSG_RESP_HYPERVISOR_HOOKS   0x22D

// Status codes
#define WINSYS_STATUS_OK            0
#define WINSYS_STATUS_ERROR         1
#define WINSYS_STATUS_NO_DRIVER     2

#pragma pack(push, 1)

typedef struct {
	uint32_t MessageType;
	uint32_t DataSize;      // payload size in bytes following this header
	uint32_t Status;
} WinSysMessageHeader;

// Network-serializable process info
typedef struct {
	uint32_t Id;
	uint32_t ParentId;
	uint32_t SessionId;
	uint32_t HandleCount;
	uint32_t ThreadCount;
	uint32_t PeakThreads;
	int64_t CreateTime;
	int64_t UserTime;
	int64_t KernelTime;
	int64_t WorkingSetPrivateSize;
	uint64_t VirtualSize;
	uint64_t PeakVirtualSize;
	uint64_t WorkingSetSize;
	uint64_t PeakWorkingSetSize;
	uint64_t PrivatePageCount;
	uint64_t PagedPoolUsage;
	uint64_t PeakPagedPoolUsage;
	uint64_t NonPagedPoolUsage;
	uint64_t PeakNonPagedPoolUsage;
	uint64_t PagefileUsage;
	uint64_t PeakPagefileUsage;
	float CPU;
	int32_t BasePriority;
	uint32_t PageFaultCount;
	uint32_t HardFaultCount;
	char ImageName[260];
	char ImagePath[520];
} ProcessInfoNet;

// Network-serializable service info
typedef struct {
	uint32_t ProcessId;
	uint32_t Type;
	uint32_t CurrentState;
	uint32_t StartType;
	uint32_t ControlsAccepted;
	char Name[256];
	char DisplayName[256];
	char BinaryPath[520];
} ServiceInfoNet;

// Network-serializable connection info
typedef struct {
	uint32_t State;
	uint32_t Pid;
	uint32_t Type;
	uint32_t LocalPort;
	uint32_t RemotePort;
	uint8_t LocalAddress[16];
	uint8_t RemoteAddress[16];
	char ModuleName[260];
} ConnectionNet;

// Network-serializable system info
typedef struct {
	uint32_t MajorVersion;
	uint32_t MinorVersion;
	uint32_t BuildNumber;
	uint32_t Revision;
	char DisplayVersion[64];
	char ProductName[128];
} SysInfoNet;

// Network-serializable kernel base info (for remote symbol resolution)
typedef struct {
	uint64_t KernelBase;
	uint32_t ImageSize;
	uint32_t PdbAge;
	uint8_t  PdbGuid[16];       // GUID as raw bytes
	char PdbFileName[128];      // e.g. "ntkrnlmp.pdb"
} KernelBaseInfoNet;

typedef struct {
	float CpuUsage;
	float MemoryUsage;
	float GpuUsage;
	float NetworkMbps;
	uint64_t TotalPhysicalBytes;
	uint64_t UptimeSeconds;
	char CpuName[128];
	char GpuName[128];
} PerformanceSnapshotNet;

typedef struct {
	uint32_t QueryType; // 1 = subkeys, 2 = values
	char Path[512];
} RegistryEnumRequestNet;

typedef struct {
	char Name[260];
} RegistryKeyNet;

typedef struct {
	uint32_t Type;
	uint32_t IsDefault;
	uint32_t DataSize;      // actual size of raw data in Data[]
	char Name[260];
	uint8_t Data[2048];     // raw registry value bytes (client formats for display)
} RegistryValueNet;

// IRP dispatch request (driver name as UTF-8)
typedef struct {
	char DriverName[256];
} IrpDispatchRequestNet;

// Handle entry
typedef struct {
	uint64_t ProcessId;
	uint16_t HandleValue;
	uint64_t Object;
	uint32_t GrantedAccess;
	uint8_t ObjectTypeIndex;
	uint16_t Attributes;
} HandleEntryNet;

// Big pool entry
typedef struct {
	uint64_t VirtualAddress;
	uint64_t SizeInBytes;
	char Tag[5];
	uint8_t NonPaged;
} BigPoolEntryNet;

// Pool tag entry
typedef struct {
	char Tag[5];
	uint8_t _pad[3];
	uint64_t PagedAllocs;
	uint64_t PagedFrees;
	uint64_t PagedUsed;
	uint64_t NonPagedAllocs;
	uint64_t NonPagedFrees;
	uint64_t NonPagedUsed;
} PoolTagEntryNet;

// Interrupt info per CPU
typedef struct {
	uint32_t ContextSwitches;
	uint32_t DpcCount;
	uint32_t DpcRate;
	uint32_t TimeIncrement;
	uint32_t DpcBypassCount;
	uint32_t ApcBypassCount;
} InterruptInfoNet;

// ETW session
typedef struct {
	char Name[256];
	uint32_t BufferSize;
	uint32_t BuffersWritten;
	uint32_t EventsLost;
	uint32_t LogFileMode;
} EtwSessionNet;

// ETW provider
typedef struct {
	char Name[256];
	char Guid[40];
} EtwProviderNet;

// Root certificate
typedef struct {
	char Subject[256];
	char Issuer[256];
	char Store[32];
	char Expires[16];
	char Thumbprint[64];
} CertificateNet;

// Network adapter
typedef struct {
	char Name[256];
	char Description[256];
	char Type[32];
	char Status[16];
	char Mac[20];
	char IpAddress[64];
	char Gateway[64];
} AdapterInfoNet;

// RPC endpoint
typedef struct {
	char InterfaceId[40];
	uint16_t MajorVersion;
	uint16_t MinorVersion;
	char Binding[256];
	char Annotation[256];
} RpcEndpointNet;

// Named pipe
typedef struct {
	char Name[260];
} NamedPipeNet;

// MiniFilter
typedef struct {
	char Name[256];
	char Altitude[64];
	uint32_t Instances;
	uint32_t FrameId;
	uint8_t IsLegacy;
} MiniFilterNet;

// Filter instance request
typedef struct {
	char FilterName[256];
} FilterInstanceRequestNet;

// Filter instance
typedef struct {
	char InstanceName[256];
	char VolumeName[256];
} FilterInstanceNet;

// Object directory request
typedef struct {
	char Path[520];
} ObjDirectoryRequestNet;

// Object directory entry
typedef struct {
	char Name[256];
	char TypeName[64];
	char SymLinkTarget[520];
	char FullPath[520];
	uint8_t IsDirectory;
} ObjectEntryNet;

// Ntdll function entry (for SSDT name resolution)
typedef struct {
	uint32_t ServiceId;
	char Name[128];
} NtdllFunctionNet;

// Instrumentation callback entry
typedef struct {
	uint32_t ProcessId;
	uint64_t InstrumentationCallback;
	char ImageName[16];
} InstrumentationCbNet;

// DSE status (raw values - client decodes flags)
typedef struct {
	uint64_t CiAddress;
	uint64_t gCiOptionsAddress;
	uint32_t gCiOptionsValue;
	uint32_t SecureBootRegValue;  // raw DWORD from registry (0xFFFFFFFF = not available)
	uint32_t VbsRegValue;         // raw DWORD from registry (0xFFFFFFFF = not available)
} DseStatusNet;

// Kernel integrity entry (client compares Expected vs Actual to determine patched status)
typedef struct {
	uint64_t FunctionAddress;
	uint64_t ExpectedFirstBytes;
	uint64_t ActualFirstBytes;
	char FunctionName[64];
} KernelIntegrityNet;

// BYOVD: raw loaded driver entry (server sends driver list, client does vulnerability matching)
typedef struct {
	char DriverName[260];
	char DriverPath[520];
} ByovdEntryNet;

// Memory read request/response
typedef struct {
	uint32_t Pid;
	uint64_t Address;
	uint32_t Size;
} MemoryReadRequestNet;

typedef struct {
	uint32_t BytesRead;
	uint8_t Data[4096];
} MemoryReadResponseNet;

// Memory write request (data follows header inline)
typedef struct {
	uint32_t Pid;
	uint64_t Address;
	uint32_t Size;
	uint8_t Data[4096];
} MemoryWriteRequestNet;

typedef struct {
	uint32_t BytesWritten;
} MemoryWriteResponseNet;

// CI Policy
typedef struct {
	uint32_t CiOptions;
} CiPolicyNet;

// Hypervisor hook entry
typedef struct {
	char FunctionName[64];
	uint64_t AvgCycles;
	uint64_t BaselineCycles;
	uint8_t TimingAnomaly;
} HypervisorHookEntryNet;

#pragma pack(pop)
