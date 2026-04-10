#pragma once
#include "..\KWinSys\KWinSysPublic.h"
#include <Windows.h>
#include <vector>

struct DriverHelper abstract final {
	static bool LoadDriver(bool load = true);
	static bool InstallDriver(bool justCopy = false);
	static bool UpdateDriver();
	static bool IsDriverLoaded();
	static bool IsDriverInstalled();
	static bool RemoveDriver();
	static unsigned short GetVersion();
	static unsigned short GetCurrentVersion();
	static bool CloseDevice();

	static MODULE_INFO* GetCallbacks(const CALLBACK_QUERY& query);
	static ULONG_PTR* GetSSDT();
	static MODULE_INFO* GetModules();
	static std::vector<KERNEL_PROCESS_ENTRY> GetProcessObjects();
	static bool SendEprocessOffsets(const EPROCESS_OFFSETS& offsets);
	static bool CrossCheckProcesses(std::vector<BYTE>& outBuffer, DWORD& outBytes);
	static bool CreateModuleSnapshot(unsigned long& count);
	static bool QueryModulePage(unsigned long startIndex, unsigned long count, KERNEL_MODULE_ENTRY* entries, unsigned long& returnedCount);
	static bool ReleaseModuleSnapshot();

	static bool GetGdt(GDT_INFO& info);
	static bool GetIdt(IDT_INFO& info);
	static bool EnumWfpFilters(std::vector<WFP_FILTER_ENTRY>& entries);
	static bool EnumWfpCallouts(std::vector<WFP_CALLOUT_ENTRY>& entries);
	static bool QueryObjectProcs(std::vector<OBJECT_TYPE_PROC_ENTRY>& entries);
	static bool GetIrpDispatch(const wchar_t* driverName, IRP_DISPATCH_RESULT& result);
	static bool QueryInstrumentationCallbacks(std::vector<INSTRUMENTATION_CB_ENTRY>& entries);
	static bool QueryDseStatus(DSE_STATUS_INFO& info);
	static bool QueryKernelIntegrity(std::vector<KERNEL_INTEGRITY_ENTRY>& entries);
	static bool QueryPatchGuardTimers(std::vector<PATCHGUARD_TIMER_ENTRY>& entries);
	static bool MemoryRead(const MEMORY_READ_REQUEST& request, MEMORY_READ_RESULT& result);
	static bool MemoryWrite(const MEMORY_WRITE_REQUEST& request, MEMORY_WRITE_RESULT& result);

private:
	static bool OpenDevice();

	static void* _hDevice;
};
