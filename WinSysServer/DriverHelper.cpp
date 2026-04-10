#include "pch.h"
#include "DriverHelper.h"
#include "..\KWinSys\KWinSysPublic.h"
#include <stdio.h>

static MODULE_INFO gg[200] = { {0} };
static ULONG_PTR ss[500] = { {0} };
static MODULE_INFO ee[200] = { {0} };

HANDLE DriverHelper::_hDevice;

bool DriverHelper::LoadDriver(bool load) {
	if (_hDevice) {
		::CloseHandle(_hDevice);
		_hDevice = nullptr;
	}
	wil::unique_schandle hScm(::OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS));
	if (!hScm)
		return false;

	wil::unique_schandle hService(::OpenService(hScm.get(), L"KWinSys", SERVICE_ALL_ACCESS));
	if (!hService)
		return false;

	SERVICE_STATUS status;
	bool success = true;
	DWORD targetState;
	::QueryServiceStatus(hService.get(), &status);
	if (load && status.dwCurrentState != (targetState = SERVICE_RUNNING))
		success = ::StartService(hService.get(), 0, nullptr);
	else if (!load && status.dwCurrentState != (targetState = SERVICE_STOPPED))
		success = ::ControlService(hService.get(), SERVICE_CONTROL_STOP, &status);
	else
		return true;

	if (!success)
		return false;

	for (int i = 0; i < 20; i++) {
		::QueryServiceStatus(hService.get(), &status);
		if (status.dwCurrentState == targetState)
			return true;
		::Sleep(200);
	}
	return false;
}

bool DriverHelper::InstallDriver(bool justCopy) {
	if (!justCopy && IsDriverLoaded()) {
		if (!LoadDriver(false)) {
			fprintf(stderr, "[!] Stop the running driver before reinstalling it\n");
			return false;
		}
		CloseDevice();
	}

	WCHAR dstPath[MAX_PATH];
	::GetSystemDirectory(dstPath, MAX_PATH);
	::wcscat_s(dstPath, L"\\Drivers\\KWinSys.sys");
	wil::unique_hfile hFile(::CreateFile(dstPath, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_SYSTEM, nullptr));
	if (!hFile) {
		fprintf(stderr, "[!] Failed to create %ls (error %lu)\n", dstPath, ::GetLastError());
		return false;
	}

	// Copy KWinSys.sys from sidecar (same directory as this exe)
	WCHAR exePath[MAX_PATH]{};
	if (!::GetModuleFileNameW(nullptr, exePath, _countof(exePath))) {
		fprintf(stderr, "[!] GetModuleFileName failed (error %lu)\n", ::GetLastError());
		return false;
	}
	WCHAR* slash = wcsrchr(exePath, L'\\');
	if (!slash) {
		fprintf(stderr, "[!] Unexpected exe path format\n");
		return false;
	}
	*slash = 0;
	WCHAR sidecarPath[MAX_PATH]{};
	::wcscpy_s(sidecarPath, exePath);
	::wcscat_s(sidecarPath, L"\\KWinSys.sys");

	wil::unique_hfile hSource(::CreateFile(sidecarPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
	if (!hSource) {
		fprintf(stderr, "[!] KWinSys.sys not found next to this executable (%ls)\n", sidecarPath);
		return false;
	}

	constexpr DWORD bufferSize = 1 << 16;
	std::vector<BYTE> buffer(bufferSize);
	for (;;) {
		DWORD read = 0, written = 0;
		if (!::ReadFile(hSource.get(), buffer.data(), bufferSize, &read, nullptr)) {
			fprintf(stderr, "[!] ReadFile failed (error %lu)\n", ::GetLastError());
			return false;
		}
		if (read == 0)
			break;
		if (!::WriteFile(hFile.get(), buffer.data(), read, &written, nullptr) || written != read) {
			fprintf(stderr, "[!] WriteFile failed (error %lu)\n", ::GetLastError());
			return false;
		}
	}

	if (justCopy)
		return true;

	// Register the kernel driver service
	wil::unique_schandle hScm(::OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS));
	if (!hScm) {
		fprintf(stderr, "[!] OpenSCManager failed (error %lu)\n", ::GetLastError());
		return false;
	}

	wil::unique_schandle hService(::CreateService(hScm.get(), L"KWinSys", nullptr, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
		SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, dstPath, nullptr, nullptr, nullptr, nullptr, nullptr));
	if (!hService) {
		auto error = ::GetLastError();
		if (error == ERROR_SERVICE_EXISTS) {
			wil::unique_schandle existing(::OpenService(hScm.get(), L"KWinSys", SERVICE_CHANGE_CONFIG));
			if (!existing) {
				fprintf(stderr, "[!] OpenService for existing driver failed (error %lu)\n", error);
				return false;
			}
			if (!::ChangeServiceConfig(existing.get(), SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_NO_CHANGE, dstPath, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr)) {
				fprintf(stderr, "[!] ChangeServiceConfig failed (error %lu)\n", ::GetLastError());
				return false;
			}
			return true;
		}
		fprintf(stderr, "[!] CreateService failed (error %lu)\n", error);
		return false;
	}
	return true;
}

bool DriverHelper::UpdateDriver() {
	CloseDevice();
	if (IsDriverLoaded() && !LoadDriver(false))
		return false;
	if (!LoadDriver())
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

	DWORD bytes;
	::DeviceIoControl(_hDevice, IOCTL_WINSYS_LIST_SSDT, nullptr, 0, &ss, sizeof(ULONG_PTR) * 500, &bytes, nullptr);

	return ss;
}

MODULE_INFO* DriverHelper::GetModules() {
	if (!OpenDevice())
		return ee;

	DWORD bytes;
	::DeviceIoControl(_hDevice, IOCTL_WINSYS_LIST_MODULES, nullptr, 0, &ee, sizeof(MODULE_INFO) * 200, &bytes, nullptr);

	return ee;
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

bool DriverHelper::CrossCheckProcesses(std::vector<BYTE>& outBuffer, DWORD& outBytes) {
	outBytes = 0;
	if (!OpenDevice())
		return false;

	ULONG bufferSize = sizeof(CROSS_CHECK_RESULT) + sizeof(CROSS_CHECK_PROCESS_ENTRY) * MAX_CROSS_CHECK_PROCESSES;
	outBuffer.resize(bufferSize, 0);

	if (!::DeviceIoControl(_hDevice, IOCTL_WINSYS_CROSS_CHECK_PROCESSES,
		nullptr, 0, outBuffer.data(), bufferSize, &outBytes, nullptr))
		return false;

	return outBytes >= sizeof(CROSS_CHECK_RESULT);
}

bool DriverHelper::SendEprocessOffsets(const EPROCESS_OFFSETS& offsets) {
	if (!OpenDevice())
		return false;

	DWORD bytes = 0;
	return ::DeviceIoControl(_hDevice, IOCTL_WINSYS_SET_EPROCESS_OFFSETS,
		(LPVOID)&offsets, sizeof(EPROCESS_OFFSETS), nullptr, 0, &bytes, nullptr) != FALSE;
}

bool DriverHelper::CreateModuleSnapshot(unsigned long& count) {
	count = 0;
	if (!OpenDevice())
		return false;

	MODULE_SNAPSHOT_INFO info{};
	DWORD bytes = 0;
	if (!::DeviceIoControl(_hDevice, IOCTL_WINSYS_CREATE_MODULE_SNAPSHOT, nullptr, 0, &info, sizeof(info), &bytes, nullptr))
		return false;
	count = info.Count;
	return true;
}

bool DriverHelper::QueryModulePage(unsigned long startIndex, unsigned long count, KERNEL_MODULE_ENTRY* entries, unsigned long& returnedCount) {
	returnedCount = 0;
	if (!OpenDevice())
		return false;

	MODULE_PAGE_REQUEST request{ startIndex, count };
	DWORD bytes = 0;
	if (!::DeviceIoControl(_hDevice, IOCTL_WINSYS_QUERY_MODULE_PAGE, &request, sizeof(request), entries, sizeof(KERNEL_MODULE_ENTRY) * count, &bytes, nullptr))
		return false;
	returnedCount = bytes / sizeof(KERNEL_MODULE_ENTRY);
	return true;
}

bool DriverHelper::ReleaseModuleSnapshot() {
	if (!OpenDevice())
		return false;

	DWORD bytes = 0;
	return ::DeviceIoControl(_hDevice, IOCTL_WINSYS_RELEASE_MODULE_SNAPSHOT, nullptr, 0, nullptr, 0, &bytes, nullptr) != FALSE;
}

USHORT DriverHelper::GetVersion() {
	USHORT version = 0;
	if (!OpenDevice())
		return 0;

	DWORD bytes;
	::DeviceIoControl(_hDevice, IOCTL_WINSYS_GET_VERSION, nullptr, 0, &version, sizeof(version), &bytes, nullptr);
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
	if (!hScm)
		return false;

	wil::unique_schandle hService(::OpenService(hScm.get(), L"KWinSys", SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS));
	if (!hService)
		return false;

	SERVICE_STATUS status{};
	::ControlService(hService.get(), SERVICE_CONTROL_STOP, &status);
	return ::DeleteService(hService.get()) != FALSE;
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

bool DriverHelper::MemoryRead(const MEMORY_READ_REQUEST& request, MEMORY_READ_RESULT& result) {
	memset(&result, 0, sizeof(result));
	if (!OpenDevice())
		return false;
	DWORD bytes = 0;
	if (!::DeviceIoControl(_hDevice, IOCTL_WINSYS_MEMORY_READ,
		(LPVOID)&request, sizeof(request), &result, sizeof(result), &bytes, nullptr))
		return false;
	return bytes >= offsetof(MEMORY_READ_RESULT, Data);
}

bool DriverHelper::MemoryWrite(const MEMORY_WRITE_REQUEST& request, MEMORY_WRITE_RESULT& result) {
	memset(&result, 0, sizeof(result));
	if (!OpenDevice())
		return false;
	DWORD bytes = 0;
	if (!::DeviceIoControl(_hDevice, IOCTL_WINSYS_MEMORY_WRITE,
		(LPVOID)&request, sizeof(request), &result, sizeof(result), &bytes, nullptr))
		return false;
	return bytes >= sizeof(MEMORY_WRITE_RESULT);
}

bool DriverHelper::OpenDevice() {
	if (!_hDevice) {
		_hDevice = ::CreateFile(L"\\\\.\\KWinSys", GENERIC_WRITE | GENERIC_READ,
			FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
			OPEN_EXISTING, 0, nullptr);
		if (_hDevice == INVALID_HANDLE_VALUE) {
			_hDevice = nullptr;
			return false;
		}
	}
	return true;
}
