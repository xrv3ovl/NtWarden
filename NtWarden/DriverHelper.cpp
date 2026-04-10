#include "pch.h"
#include "DriverHelper.h"
#include "SecurityHelper.h"
#include "..\KWinSys\KWinSysPublic.h"
#include "LoggerView.h"


static MODULE_INFO gg[200] = { {0} };
static ULONG_PTR ss[500] = { {0} };
static MODULE_INFO ee[200] = { {0} };

HANDLE DriverHelper::_hDevice;
wchar_t DriverHelper::_lastErrorText[512] = L"";

void DriverHelper::SetLastErrorText(const wchar_t* text) {
	::wcsncpy_s(_lastErrorText, text ? text : L"", _TRUNCATE);
}

void DriverHelper::SetLastErrorFromWin32(const wchar_t* context, DWORD error) {
	wchar_t systemMessage[320]{};
	::FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		nullptr, error, 0, systemMessage, _countof(systemMessage), nullptr);
	::swprintf_s(_lastErrorText, L"%s (Win32=%lu: %s)", context, error, systemMessage[0] ? systemMessage : L"Unknown error");
}

bool DriverHelper::LoadDriver(bool load) {
	if (_hDevice) {
		::CloseHandle(_hDevice);
		_hDevice = nullptr;
	}
	wil::unique_schandle hScm(::OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS));
	if (!hScm) {
		SetLastErrorFromWin32(L"OpenSCManager failed");
		return false;
	}

	wil::unique_schandle hService(::OpenService(hScm.get(), L"KWinSys", SERVICE_ALL_ACCESS));
	if (!hService) {
		SetLastErrorFromWin32(L"OpenService failed");
		return false;
	}

	SERVICE_STATUS status;
	bool success = true;
	DWORD targetState;
	if (!::QueryServiceStatus(hService.get(), &status)) {
		SetLastErrorFromWin32(L"QueryServiceStatus failed");
		return false;
	}
	if (load && status.dwCurrentState != (targetState = SERVICE_RUNNING))
		success = ::StartService(hService.get(), 0, nullptr);
	else if (!load && status.dwCurrentState != (targetState = SERVICE_STOPPED))
		success = ::ControlService(hService.get(), SERVICE_CONTROL_STOP, &status);
	else
		return true;

	if (!success) {
		SetLastErrorFromWin32(load ? L"StartService failed" : L"ControlService(STOP) failed");
		return false;
	}

	for (int i = 0; i < 20; i++) {
		if (!::QueryServiceStatus(hService.get(), &status)) {
			SetLastErrorFromWin32(L"QueryServiceStatus failed");
			return false;
		}
		if (status.dwCurrentState == targetState)
			return true;
		::Sleep(200);
	}
	SetLastErrorText(load ? L"Timed out while waiting for driver to start" : L"Timed out while waiting for driver to stop");
	return false;
}

bool DriverHelper::InstallDriver(bool justCopy) {
	if (!SecurityHelper::IsRunningElevated()) {
		SetLastErrorText(L"Administrative privileges are required to install the driver");
		return false;
	}

	if (!justCopy && IsDriverLoaded()) {
		if (!LoadDriver(false)) {
			SetLastErrorText(L"Stop the running driver before reinstalling it");
			return false;
		}
		CloseDevice();
	}

	WCHAR path[MAX_PATH];
	::GetSystemDirectory(path, MAX_PATH);
	::wcscat_s(path, L"\\Drivers\\KWinSys.sys");
	wil::unique_hfile hFile(::CreateFile(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_SYSTEM, nullptr));
	if (!hFile) {
		if (::GetLastError() == ERROR_SHARING_VIOLATION)
			SetLastErrorText(L"KWinSys.sys is locked. Stop the driver and close any app using it before reinstalling");
		else
		SetLastErrorFromWin32(L"CreateFile for KWinSys.sys failed");
		return false;
	}

	DWORD bytes = 0;
	bool copied = false;

	WCHAR exePath[MAX_PATH]{};
	if (::GetModuleFileNameW(nullptr, exePath, _countof(exePath))) {
		WCHAR* slash = wcsrchr(exePath, L'\\');
		if (slash) {
			*slash = 0;
			WCHAR sidecarPath[MAX_PATH]{};
			::wcscpy_s(sidecarPath, exePath);
			::wcscat_s(sidecarPath, L"\\KWinSys.sys");

			wil::unique_hfile hSource(::CreateFile(sidecarPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
			if (hSource) {
				constexpr DWORD bufferSize = 1 << 16;
				std::vector<BYTE> buffer(bufferSize);
				for (;;) {
					DWORD read = 0;
					DWORD written = 0;
					if (!::ReadFile(hSource.get(), buffer.data(), bufferSize, &read, nullptr)) {
						SetLastErrorFromWin32(L"ReadFile for sidecar KWinSys.sys failed");
						return false;
					}
					if (read == 0)
						break;
					if (!::WriteFile(hFile.get(), buffer.data(), read, &written, nullptr) || written != read) {
						SetLastErrorFromWin32(L"WriteFile for KWinSys.sys failed");
						return false;
					}
				}
				copied = true;
			}
		}
	}

	if (!copied) {
		SetLastErrorText(L"KWinSys.sys not found next to the executable");
		return false;
	}

	if (justCopy)
		return true;

	wil::unique_schandle hScm(::OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS));
	if (!hScm) {
		SetLastErrorFromWin32(L"OpenSCManager failed");
		return false;
	}

	wil::unique_schandle hService(::CreateService(hScm.get(), L"KWinSys", nullptr, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
		SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, path, nullptr, nullptr, nullptr, nullptr, nullptr));
	if (!hService) {
		auto error = ::GetLastError();
		if (error == ERROR_SERVICE_EXISTS) {
			wil::unique_schandle existing(::OpenService(hScm.get(), L"KWinSys", SERVICE_CHANGE_CONFIG | SERVICE_QUERY_STATUS));
			if (!existing) {
				SetLastErrorFromWin32(L"OpenService for existing driver failed", error);
				return false;
			}
			if (!::ChangeServiceConfig(existing.get(), SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_NO_CHANGE, path, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr)) {
				SetLastErrorFromWin32(L"ChangeServiceConfig failed");
				return false;
			}
			return true;
		}
		SetLastErrorFromWin32(L"CreateService failed", error);
		return false;
	}
	return true;
}

bool DriverHelper::UpdateDriver() {
	CloseDevice();
	if (IsDriverLoaded() && !LoadDriver(false))
		return false;
	if (!InstallDriver(true))
		return false;
	if (!LoadDriver())
		return false;
	if (!VerifyLoadedDriverVersion())
		return false;

	return true;
}

MODULE_INFO* DriverHelper::GetCallbacks(const CALLBACK_QUERY& query) {
	if (!OpenDevice())
		return gg;

	DWORD bytes = 0;
	::DeviceIoControl(_hDevice, IOCTL_WINSYS_LIST_CALLBACKS,
		(LPVOID)&query, sizeof(query),
		&gg, sizeof(MODULE_INFO) * 200, &bytes, nullptr);

	return gg;
}

ULONG_PTR* DriverHelper::GetSSDT() {
	if (!OpenDevice())
		return ss;

	DWORD bytes = 0;

	::DeviceIoControl(_hDevice, IOCTL_WINSYS_LIST_SSDT, nullptr, 0, &ss, sizeof(ULONG_PTR) * 500, &bytes, nullptr);

	return ss;
}

std::vector<KERNEL_PROCESS_ENTRY> DriverHelper::GetProcessObjects() {
	std::vector<KERNEL_PROCESS_ENTRY> result;
	if (!OpenDevice())
		return result;

	ULONG bufferSize = sizeof(ULONG) + sizeof(KERNEL_PROCESS_ENTRY) * MAX_KERNEL_PROCESSES;
	std::vector<BYTE> buffer(bufferSize, 0);
	DWORD bytes = 0;

	if (!::DeviceIoControl(_hDevice, IOCTL_WINSYS_ENUM_PROCESS_OBJECTS,
		nullptr, 0, buffer.data(), bufferSize, &bytes, nullptr))
		return result;

	if (bytes < sizeof(ULONG))
		return result;

	ULONG count = *(ULONG*)buffer.data();
	if (count > MAX_KERNEL_PROCESSES)
		count = MAX_KERNEL_PROCESSES;

	KERNEL_PROCESS_ENTRY* entries = (KERNEL_PROCESS_ENTRY*)(buffer.data() + sizeof(ULONG));
	result.assign(entries, entries + count);
	return result;
}

DriverHelper::CrossCheckResult DriverHelper::CrossCheckProcesses() {
	CrossCheckResult result{};
	if (!OpenDevice())
		return result;

	ULONG bufferSize = sizeof(CROSS_CHECK_RESULT) + sizeof(CROSS_CHECK_PROCESS_ENTRY) * MAX_CROSS_CHECK_PROCESSES;
	std::vector<BYTE> buffer(bufferSize, 0);
	DWORD bytes = 0;

	if (!::DeviceIoControl(_hDevice, IOCTL_WINSYS_CROSS_CHECK_PROCESSES,
		nullptr, 0, buffer.data(), bufferSize, &bytes, nullptr))
		return result;

	if (bytes < sizeof(CROSS_CHECK_RESULT))
		return result;

	result.header = *(CROSS_CHECK_RESULT*)buffer.data();
	if (result.header.TotalEntries > MAX_CROSS_CHECK_PROCESSES)
		result.header.TotalEntries = MAX_CROSS_CHECK_PROCESSES;

	CROSS_CHECK_PROCESS_ENTRY* entries = (CROSS_CHECK_PROCESS_ENTRY*)(buffer.data() + sizeof(CROSS_CHECK_RESULT));
	result.entries.assign(entries, entries + result.header.TotalEntries);
	return result;
}

bool DriverHelper::SendEprocessOffsets(const EPROCESS_OFFSETS& offsets) {
	if (!OpenDevice())
		return false;

	DWORD bytes = 0;
	if (!::DeviceIoControl(_hDevice, IOCTL_WINSYS_SET_EPROCESS_OFFSETS,
		(LPVOID)&offsets, sizeof(EPROCESS_OFFSETS), nullptr, 0, &bytes, nullptr)) {
		SetLastErrorFromWin32(L"Send EPROCESS offsets failed");
		return false;
	}
	return true;
}

MODULE_INFO* DriverHelper::GetModules() {
	if (!OpenDevice())
		return ee;

	DWORD bytes = 0;

	::DeviceIoControl(_hDevice, IOCTL_WINSYS_LIST_MODULES, nullptr, 0, &ee, sizeof(MODULE_INFO) * 200, &bytes, nullptr);

	return ee;
}

bool DriverHelper::CreateModuleSnapshot(unsigned long& count) {
	count = 0;
	if (!OpenDevice())
		return false;

	MODULE_SNAPSHOT_INFO info{};
	DWORD bytes = 0;
	if (!::DeviceIoControl(_hDevice, IOCTL_WINSYS_CREATE_MODULE_SNAPSHOT, nullptr, 0, &info, sizeof(info), &bytes, nullptr)) {
		SetLastErrorFromWin32(L"Create module snapshot failed");
		return false;
	}
	count = info.Count;
	return true;
}

bool DriverHelper::QueryModulePage(unsigned long startIndex, unsigned long count, KERNEL_MODULE_ENTRY* entries, unsigned long& returnedCount) {
	returnedCount = 0;
	if (!OpenDevice())
		return false;

	MODULE_PAGE_REQUEST request{ startIndex, count };
	DWORD bytes = 0;
	if (!::DeviceIoControl(_hDevice, IOCTL_WINSYS_QUERY_MODULE_PAGE, &request, sizeof(request), entries, sizeof(KERNEL_MODULE_ENTRY) * count, &bytes, nullptr)) {
		SetLastErrorFromWin32(L"Query module page failed");
		return false;
	}
	returnedCount = bytes / sizeof(KERNEL_MODULE_ENTRY);
	return true;
}

bool DriverHelper::ReleaseModuleSnapshot() {
	if (!OpenDevice())
		return false;

	DWORD bytes = 0;
	if (!::DeviceIoControl(_hDevice, IOCTL_WINSYS_RELEASE_MODULE_SNAPSHOT, nullptr, 0, nullptr, 0, &bytes, nullptr)) {
		SetLastErrorFromWin32(L"Release module snapshot failed");
		return false;
	}
	return true;
}

bool DriverHelper::GetGdt(GDT_INFO& info) {
	RtlZeroMemory(&info, sizeof(info));
	if (!OpenDevice())
		return false;
	DWORD bytes = 0;
	return ::DeviceIoControl(_hDevice, IOCTL_WINSYS_QUERY_GDT, nullptr, 0, &info, sizeof(info), &bytes, nullptr) != FALSE;
}

bool DriverHelper::GetIdt(IDT_INFO& info) {
	RtlZeroMemory(&info, sizeof(info));
	if (!OpenDevice())
		return false;
	DWORD bytes = 0;
	return ::DeviceIoControl(_hDevice, IOCTL_WINSYS_QUERY_IDT, nullptr, 0, &info, sizeof(info), &bytes, nullptr) != FALSE;
}


bool DriverHelper::GetIrpDispatch(const wchar_t* driverName, IRP_DISPATCH_RESULT& result) {
	RtlZeroMemory(&result, sizeof(result));
	if (!OpenDevice())
		return false;
	IRP_DISPATCH_REQUEST request{};
	wcsncpy_s(request.DriverName, driverName, 255);
	DWORD bytes = 0;
	return ::DeviceIoControl(_hDevice, IOCTL_WINSYS_QUERY_IRP_DISPATCH,
		&request, sizeof(request), &result, sizeof(result), &bytes, nullptr) != FALSE;
}

bool DriverHelper::QueryObjectProcs(std::vector<OBJECT_TYPE_PROC_ENTRY>& entries) {
	entries.clear();
	if (!OpenDevice())
		return false;
	ULONG bufSize = sizeof(OBJECT_TYPE_PROC_RESULT) + sizeof(OBJECT_TYPE_PROC_ENTRY) * MAX_OBJECT_TYPES;
	std::vector<BYTE> buffer(bufSize, 0);
	DWORD bytes = 0;
	if (!::DeviceIoControl(_hDevice, IOCTL_WINSYS_QUERY_OBJECT_PROCS,
		nullptr, 0, buffer.data(), bufSize, &bytes, nullptr))
		return false;
	if (bytes < sizeof(OBJECT_TYPE_PROC_RESULT))
		return false;
	auto* header = (OBJECT_TYPE_PROC_RESULT*)buffer.data();
	auto* e = (OBJECT_TYPE_PROC_ENTRY*)(buffer.data() + sizeof(OBJECT_TYPE_PROC_RESULT));
	ULONG count = header->Count;
	if (count > MAX_OBJECT_TYPES) count = MAX_OBJECT_TYPES;
	entries.assign(e, e + count);
	return true;
}

bool DriverHelper::EnumIoTimers(const IO_TIMER_QUERY& query, std::vector<IO_TIMER_ENTRY>& entries) {
	entries.clear();
	if (!OpenDevice())
		return false;
	ULONG bufSize = sizeof(IO_TIMER_RESULT) + sizeof(IO_TIMER_ENTRY) * MAX_IO_TIMERS;
	std::vector<BYTE> buffer(bufSize, 0);
	DWORD bytes = 0;
	if (!::DeviceIoControl(_hDevice, IOCTL_WINSYS_ENUM_IO_TIMERS,
		(LPVOID)&query, sizeof(query), buffer.data(), bufSize, &bytes, nullptr))
		return false;
	if (bytes < sizeof(IO_TIMER_RESULT))
		return false;
	auto* header = (IO_TIMER_RESULT*)buffer.data();
	auto* e = (IO_TIMER_ENTRY*)(buffer.data() + sizeof(IO_TIMER_RESULT));
	ULONG count = header->Count;
	if (count > MAX_IO_TIMERS) count = MAX_IO_TIMERS;
	entries.assign(e, e + count);
	return true;
}

bool DriverHelper::EnumWfpFilters(std::vector<WFP_FILTER_ENTRY>& entries) {
	entries.clear();
	if (!OpenDevice())
		return false;
	ULONG bufSize = sizeof(WFP_FILTER_RESULT) + sizeof(WFP_FILTER_ENTRY) * MAX_WFP_FILTERS;
	std::vector<BYTE> buffer(bufSize, 0);
	DWORD bytes = 0;
	if (!::DeviceIoControl(_hDevice, IOCTL_WINSYS_ENUM_WFP_FILTERS,
		nullptr, 0, buffer.data(), bufSize, &bytes, nullptr))
		return false;
	if (bytes < sizeof(WFP_FILTER_RESULT))
		return false;
	auto* header = (WFP_FILTER_RESULT*)buffer.data();
	auto* e = (WFP_FILTER_ENTRY*)(buffer.data() + sizeof(WFP_FILTER_RESULT));
	ULONG count = header->Count;
	if (count > MAX_WFP_FILTERS) count = MAX_WFP_FILTERS;
	entries.assign(e, e + count);
	return true;
}

bool DriverHelper::EnumWfpCallouts(std::vector<WFP_CALLOUT_ENTRY>& entries) {
	entries.clear();
	if (!OpenDevice())
		return false;
	ULONG bufSize = sizeof(WFP_CALLOUT_RESULT) + sizeof(WFP_CALLOUT_ENTRY) * MAX_WFP_CALLOUTS;
	std::vector<BYTE> buffer(bufSize, 0);
	DWORD bytes = 0;
	if (!::DeviceIoControl(_hDevice, IOCTL_WINSYS_ENUM_WFP_CALLOUTS,
		nullptr, 0, buffer.data(), bufSize, &bytes, nullptr))
		return false;
	if (bytes < sizeof(WFP_CALLOUT_RESULT))
		return false;
	auto* header = (WFP_CALLOUT_RESULT*)buffer.data();
	auto* e = (WFP_CALLOUT_ENTRY*)(buffer.data() + sizeof(WFP_CALLOUT_RESULT));
	ULONG count = header->Count;
	if (count > MAX_WFP_CALLOUTS) count = MAX_WFP_CALLOUTS;
	entries.assign(e, e + count);
	return true;
}

bool DriverHelper::MemoryRead(const MEMORY_READ_REQUEST& request, MEMORY_READ_RESULT& result) {
	RtlZeroMemory(&result, sizeof(result));
	if (!OpenDevice())
		return false;
	DWORD bytes = 0;
	if (!::DeviceIoControl(_hDevice, IOCTL_WINSYS_MEMORY_READ,
		(LPVOID)&request, sizeof(request), &result, sizeof(result), &bytes, nullptr)) {
		SetLastErrorFromWin32(L"Kernel memory read failed");
		return false;
	}
	return true;
}

bool DriverHelper::MemoryWrite(const MEMORY_WRITE_REQUEST& request, MEMORY_WRITE_RESULT& result) {
	RtlZeroMemory(&result, sizeof(result));
	if (!OpenDevice())
		return false;
	DWORD bytes = 0;
	if (!::DeviceIoControl(_hDevice, IOCTL_WINSYS_MEMORY_WRITE,
		(LPVOID)&request, sizeof(request), &result, sizeof(result), &bytes, nullptr)) {
		SetLastErrorFromWin32(L"Kernel memory write failed");
		return false;
	}
	return true;
}


bool DriverHelper::QueryKernelLogs(unsigned long startSequence, std::vector<KERNEL_LOG_ENTRY>& entries, unsigned long& nextSequence) {
	entries.clear();
	nextSequence = startSequence;
	if (!OpenDevice())
		return false;

	KERNEL_LOG_QUERY request{};
	request.StartSequence = startSequence;

	ULONG bufSize = sizeof(KERNEL_LOG_RESULT) + sizeof(KERNEL_LOG_ENTRY) * MAX_KERNEL_LOG_ENTRIES;
	std::vector<BYTE> buffer(bufSize, 0);
	DWORD bytes = 0;
	if (!::DeviceIoControl(_hDevice, IOCTL_WINSYS_QUERY_KERNEL_LOGS,
		&request, sizeof(request), buffer.data(), bufSize, &bytes, nullptr)) {
		SetLastErrorFromWin32(L"Kernel log query failed");
		return false;
	}
	if (bytes < sizeof(KERNEL_LOG_RESULT))
		return false;

	auto* header = (KERNEL_LOG_RESULT*)buffer.data();
	auto* e = (KERNEL_LOG_ENTRY*)(buffer.data() + sizeof(KERNEL_LOG_RESULT));
	ULONG count = header->Count;
	if (count > MAX_KERNEL_LOG_ENTRIES)
		count = MAX_KERNEL_LOG_ENTRIES;

	nextSequence = header->NextSequence;
	entries.assign(e, e + count);
	return true;
}

bool DriverHelper::QueryInstrumentationCallbacks(std::vector<INSTRUMENTATION_CB_ENTRY>& entries) {
	entries.clear();
	if (!OpenDevice())
		return false;
	ULONG bufSize = sizeof(INSTRUMENTATION_CB_RESULT) + sizeof(INSTRUMENTATION_CB_ENTRY) * MAX_INSTRUMENTATION_CB_ENTRIES;
	std::vector<BYTE> buffer(bufSize, 0);
	DWORD bytes = 0;
	if (!::DeviceIoControl(_hDevice, IOCTL_WINSYS_QUERY_INSTRUMENTATION_CB,
		nullptr, 0, buffer.data(), bufSize, &bytes, nullptr))
		return false;
	if (bytes < sizeof(INSTRUMENTATION_CB_RESULT))
		return false;
	auto* header = (INSTRUMENTATION_CB_RESULT*)buffer.data();
	auto* e = (INSTRUMENTATION_CB_ENTRY*)(buffer.data() + sizeof(INSTRUMENTATION_CB_RESULT));
	ULONG count = header->Count;
	if (count > MAX_INSTRUMENTATION_CB_ENTRIES) count = MAX_INSTRUMENTATION_CB_ENTRIES;
	entries.assign(e, e + count);
	return true;
}

bool DriverHelper::SnapshotCallbacks(unsigned long& snapshotId, unsigned long& entryCount) {
	snapshotId = 0; entryCount = 0;
	if (!OpenDevice())
		return false;
	CALLBACK_SNAPSHOT_REQUEST request{};
	request.SnapshotId = 0; // take new snapshot
	CALLBACK_SNAPSHOT_RESULT result{};
	DWORD bytes = 0;
	if (!::DeviceIoControl(_hDevice, IOCTL_WINSYS_SNAPSHOT_CALLBACKS,
		&request, sizeof(request), &result, sizeof(result), &bytes, nullptr))
		return false;
	snapshotId = result.SnapshotId;
	entryCount = result.EntryCount;
	return true;
}

bool DriverHelper::DiffCallbacks(unsigned long snapshotId, std::vector<CALLBACK_DIFF_ENTRY>& entries) {
	entries.clear();
	if (!OpenDevice())
		return false;
	CALLBACK_SNAPSHOT_REQUEST request{};
	request.SnapshotId = snapshotId;
	ULONG bufSize = sizeof(CALLBACK_SNAPSHOT_RESULT) + sizeof(CALLBACK_DIFF_ENTRY) * MAX_CALLBACK_SNAPSHOT_ENTRIES;
	std::vector<BYTE> buffer(bufSize, 0);
	DWORD bytes = 0;
	if (!::DeviceIoControl(_hDevice, IOCTL_WINSYS_DIFF_CALLBACKS,
		&request, sizeof(request), buffer.data(), bufSize, &bytes, nullptr))
		return false;
	if (bytes < sizeof(CALLBACK_SNAPSHOT_RESULT))
		return false;
	auto* header = (CALLBACK_SNAPSHOT_RESULT*)buffer.data();
	auto* e = (CALLBACK_DIFF_ENTRY*)(buffer.data() + sizeof(CALLBACK_SNAPSHOT_RESULT));
	ULONG count = header->EntryCount;
	if (count > MAX_CALLBACK_SNAPSHOT_ENTRIES) count = MAX_CALLBACK_SNAPSHOT_ENTRIES;
	entries.assign(e, e + count);
	return true;
}

bool DriverHelper::EnumApcQueue(const APC_QUERY& query, std::vector<APC_ENTRY>& entries) {
	entries.clear();
	if (!OpenDevice())
		return false;
	ULONG bufSize = sizeof(APC_RESULT) + sizeof(APC_ENTRY) * MAX_APC_ENTRIES;
	std::vector<BYTE> buffer(bufSize, 0);
	DWORD bytes = 0;
	if (!::DeviceIoControl(_hDevice, IOCTL_WINSYS_ENUM_APC,
		(LPVOID)&query, sizeof(query), buffer.data(), bufSize, &bytes, nullptr))
		return false;
	if (bytes < sizeof(APC_RESULT))
		return false;
	auto* header = (APC_RESULT*)buffer.data();
	auto* e = (APC_ENTRY*)(buffer.data() + sizeof(APC_RESULT));
	ULONG count = header->Count;
	if (count > MAX_APC_ENTRIES) count = MAX_APC_ENTRIES;
	entries.assign(e, e + count);
	return true;
}

bool DriverHelper::QueryDseStatus(DSE_STATUS_INFO& info) {
	RtlZeroMemory(&info, sizeof(info));
	if (!OpenDevice())
		return false;
	DWORD bytes = 0;
	return ::DeviceIoControl(_hDevice, IOCTL_WINSYS_QUERY_DSE_STATUS,
		nullptr, 0, &info, sizeof(info), &bytes, nullptr) != FALSE;
}

bool DriverHelper::QueryKernelIntegrity(std::vector<KERNEL_INTEGRITY_ENTRY>& entries) {
	entries.clear();
	if (!OpenDevice())
		return false;
	ULONG bufSize = sizeof(KERNEL_INTEGRITY_RESULT) + sizeof(KERNEL_INTEGRITY_ENTRY) * MAX_KERNEL_INTEGRITY_ENTRIES;
	std::vector<BYTE> buffer(bufSize, 0);
	DWORD bytes = 0;
	if (!::DeviceIoControl(_hDevice, IOCTL_WINSYS_QUERY_KERNEL_INTEGRITY,
		nullptr, 0, buffer.data(), bufSize, &bytes, nullptr))
		return false;
	if (bytes < sizeof(KERNEL_INTEGRITY_RESULT))
		return false;
	auto* header = (KERNEL_INTEGRITY_RESULT*)buffer.data();
	auto* e = (KERNEL_INTEGRITY_ENTRY*)(buffer.data() + sizeof(KERNEL_INTEGRITY_RESULT));
	ULONG count = header->Count;
	if (count > MAX_KERNEL_INTEGRITY_ENTRIES) count = MAX_KERNEL_INTEGRITY_ENTRIES;
	entries.assign(e, e + count);
	return true;
}

bool DriverHelper::QueryPatchGuardTimers(std::vector<PATCHGUARD_TIMER_ENTRY>& entries) {
	entries.clear();
	if (!OpenDevice())
		return false;
	ULONG bufSize = sizeof(PATCHGUARD_TIMER_RESULT) + sizeof(PATCHGUARD_TIMER_ENTRY) * MAX_PATCHGUARD_ENTRIES;
	std::vector<BYTE> buffer(bufSize, 0);
	DWORD bytes = 0;
	if (!::DeviceIoControl(_hDevice, IOCTL_WINSYS_QUERY_PATCHGUARD_TIMERS,
		nullptr, 0, buffer.data(), bufSize, &bytes, nullptr))
		return false;
	if (bytes < sizeof(PATCHGUARD_TIMER_RESULT))
		return false;
	auto* header = (PATCHGUARD_TIMER_RESULT*)buffer.data();
	auto* e = (PATCHGUARD_TIMER_ENTRY*)(buffer.data() + sizeof(PATCHGUARD_TIMER_RESULT));
	ULONG count = header->Count;
	if (count > MAX_PATCHGUARD_ENTRIES) count = MAX_PATCHGUARD_ENTRIES;
	entries.assign(e, e + count);
	return true;
}

USHORT DriverHelper::GetVersion() {
	USHORT version = 0;
	if (!OpenDevice())
		return 0;

	DWORD bytes;
	if (!::DeviceIoControl(_hDevice, IOCTL_WINSYS_GET_VERSION, nullptr, 0, &version, sizeof(version), &bytes, nullptr)) {
		SetLastErrorFromWin32(L"Query driver version failed");
		return 0;
	}
	if (bytes != sizeof(version)) {
		SetLastErrorText(L"Query driver version returned an unexpected size");
		return 0;
	}
	return version;
}

USHORT DriverHelper::GetCurrentVersion() {
	return KWINSYS_PROTOCOL_VERSION;
}

bool DriverHelper::CloseDevice() {
	if (_hDevice) {
		::CloseHandle(_hDevice);
		_hDevice = nullptr;
	}
	return true;
}

bool DriverHelper::IsDriverLoaded() {
	wil::unique_schandle hScm(::OpenSCManager(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE));
	if (!hScm)
		return false;

	wil::unique_schandle hService(::OpenService(hScm.get(), L"KWinSys", SERVICE_QUERY_STATUS));
	if (!hService)
		return false;

	SERVICE_STATUS status;
	if (!::QueryServiceStatus(hService.get(), &status))
		return false;

	return status.dwCurrentState == SERVICE_RUNNING;
}

bool DriverHelper::IsDriverInstalled() {
	wil::unique_schandle hScm(::OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT));
	if (!hScm)
		return false;

	wil::unique_schandle hService(::OpenService(hScm.get(), L"KWinSys", SERVICE_QUERY_STATUS));
	return hService != nullptr;
}

bool DriverHelper::RemoveDriver() {
	if (_hDevice)
		CloseDevice();

	wil::unique_schandle hScm(::OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS));
	if (!hScm) {
		SetLastErrorFromWin32(L"OpenSCManager failed");
		return false;
	}

	wil::unique_schandle hService(::OpenService(hScm.get(), L"KWinSys", SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS));
	if (!hService) {
		SetLastErrorFromWin32(L"OpenService failed");
		return false;
	}

	SERVICE_STATUS status{};
	::ControlService(hService.get(), SERVICE_CONTROL_STOP, &status);
	if (!::DeleteService(hService.get())) {
		SetLastErrorFromWin32(L"DeleteService failed");
		return false;
	}
	return true;
}

const wchar_t* DriverHelper::GetLastErrorText() {
	return _lastErrorText;
}

bool DriverHelper::VerifyLoadedDriverVersion() {
	CloseDevice();
	const auto version = GetVersion();
	if (version == 0)
		return false;
	if (version != GetCurrentVersion()) {
		wchar_t text[128]{};
		::swprintf_s(text, L"Loaded driver version mismatch. Found 0x%04X, expected 0x%04X", version, GetCurrentVersion());
		SetLastErrorText(text);
		return false;
	}
	return true;
}

bool DriverHelper::OpenDevice() {
	if (_hDevice == nullptr || _hDevice == INVALID_HANDLE_VALUE) {
		_hDevice = ::CreateFile(L"\\\\.\\KWinSys", GENERIC_WRITE | GENERIC_READ,
			FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
			OPEN_EXISTING, 0, nullptr);
		if (_hDevice == INVALID_HANDLE_VALUE) {
			_hDevice = nullptr;
			SetLastErrorFromWin32(L"Open driver device failed");
			return false;
		}
	}
	return true;
}
