#pragma once
#include "../KWinSys/KWinSysPublic.h"
#include <Windows.h>
#include <vector>

struct DriverHelper abstract final {
	static bool LoadDriver(bool load = true);
	static bool InstallDriver(bool justCopy = false);
	static bool UpdateDriver();
	static bool IsDriverLoaded();
	static bool IsDriverInstalled();
	static bool RemoveDriver();
	static const wchar_t* GetLastErrorText();
	static bool VerifyLoadedDriverVersion();
	static unsigned short GetVersion();
	static unsigned short GetCurrentVersion();
	static bool CloseDevice();

	static MODULE_INFO* GetCallbacks(const CALLBACK_QUERY& query);
	static ULONG_PTR* GetSSDT();
	static MODULE_INFO* GetModules();
	static std::vector<KERNEL_PROCESS_ENTRY> GetProcessObjects();
	static bool SendEprocessOffsets(const EPROCESS_OFFSETS& offsets);
	struct CrossCheckResult {
		CROSS_CHECK_RESULT header;
		std::vector<CROSS_CHECK_PROCESS_ENTRY> entries;
	};
	static CrossCheckResult CrossCheckProcesses();
	static bool CreateModuleSnapshot(unsigned long& count);
	static bool QueryModulePage(unsigned long startIndex, unsigned long count, KERNEL_MODULE_ENTRY* entries, unsigned long& returnedCount);
	static bool ReleaseModuleSnapshot();

	// Descriptor Tables
	static bool GetGdt(GDT_INFO& info);
	static bool GetIdt(IDT_INFO& info);

// IRP Dispatch
	static bool GetIrpDispatch(const wchar_t* driverName, IRP_DISPATCH_RESULT& result);

	// Object Type Procedures
	static bool QueryObjectProcs(std::vector<OBJECT_TYPE_PROC_ENTRY>& entries);

	// IO Timers
	static bool EnumIoTimers(const IO_TIMER_QUERY& query, std::vector<IO_TIMER_ENTRY>& entries);

	// WFP
	static bool EnumWfpFilters(std::vector<WFP_FILTER_ENTRY>& entries);
	static bool EnumWfpCallouts(std::vector<WFP_CALLOUT_ENTRY>& entries);

	// Kernel Memory
	static bool MemoryRead(const MEMORY_READ_REQUEST& request, MEMORY_READ_RESULT& result);
	static bool MemoryWrite(const MEMORY_WRITE_REQUEST& request, MEMORY_WRITE_RESULT& result);

// Kernel Log Stream
	static bool QueryKernelLogs(unsigned long startSequence, std::vector<KERNEL_LOG_ENTRY>& entries, unsigned long& nextSequence);

	// Instrumentation Callback Detection
	static bool QueryInstrumentationCallbacks(std::vector<INSTRUMENTATION_CB_ENTRY>& entries);

	// Callback Snapshot / Diff
	static bool SnapshotCallbacks(unsigned long& snapshotId, unsigned long& entryCount);
	static bool DiffCallbacks(unsigned long snapshotId, std::vector<CALLBACK_DIFF_ENTRY>& entries);

	// APC Queue
	static bool EnumApcQueue(const APC_QUERY& query, std::vector<APC_ENTRY>& entries);

	// DSE Status
	static bool QueryDseStatus(DSE_STATUS_INFO& info);

	// Kernel Integrity
	static bool QueryKernelIntegrity(std::vector<KERNEL_INTEGRITY_ENTRY>& entries);

	// PatchGuard Timer Detection
	static bool QueryPatchGuardTimers(std::vector<PATCHGUARD_TIMER_ENTRY>& entries);

private:
	static bool OpenDevice();
	static void SetLastErrorText(const wchar_t* text);
	static void SetLastErrorFromWin32(const wchar_t* context, DWORD error = ::GetLastError());

	static void* _hDevice;
	static wchar_t _lastErrorText[512];
};
