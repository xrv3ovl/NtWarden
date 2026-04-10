#include "pch.h"
#include "ServerHandler.h"
#include <stdio.h>
#include <intrin.h>
#include <iphlpapi.h>
#include <pdh.h>
#include <pdhmsg.h>
#include <string>
#include <sstream>

#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Pdh.lib")

// Include Psapi for EnumDeviceDrivers/GetDeviceDriverFileNameW (used by HandleKernelBase).
// Must undef the EnumProcesses macro to avoid conflicts with WinSys::ProcessManager::EnumProcesses.
#include <Psapi.h>
#undef EnumProcesses

#include <wincrypt.h>
#include <fltUser.h>
#include <evntrace.h>
#include <tdh.h>
#include <rpc.h>
#include <rpcdce.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "FltLib.lib")
#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "Rpcrt4.lib")

// Wide string to UTF-8 helper
static std::string WideToUtf8(const std::wstring& wide) {
	if (wide.empty()) return {};
	int size = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), (int)wide.size(), nullptr, 0, nullptr, nullptr);
	std::string result(size, 0);
	WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), (int)wide.size(), result.data(), size, nullptr, nullptr);
	return result;
}

static std::wstring Utf8ToWide(const char* utf8) {
	if (!utf8 || !utf8[0])
		return {};
	int size = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, nullptr, 0);
	if (size <= 1)
		return {};
	std::wstring result(size - 1, L'\0');
	MultiByteToWideChar(CP_UTF8, 0, utf8, -1, result.data(), size);
	return result;
}

namespace {
	std::string GetCpuName() {
		HKEY hKey;
		if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
			char buffer[128]{};
			DWORD bufferSize = sizeof(buffer);
			if (RegQueryValueExA(hKey, "ProcessorNameString", nullptr, nullptr, reinterpret_cast<LPBYTE>(buffer), &bufferSize) == ERROR_SUCCESS) {
				RegCloseKey(hKey);
				return buffer;
			}
			RegCloseKey(hKey);
		}
		return "Unknown CPU";
	}

	std::string GetGpuName() {
		return "Remote GPU";
	}

	class GpuUsageSampler {
	public:
		float Sample() {
			if (!_initialized)
				Initialize();
			if (!_initialized || _disabled)
				return 0.0f;

			if (ERROR_SUCCESS != ::PdhCollectQueryData(_query))
				return 0.0f;

			DWORD bufferSize = 0;
			DWORD itemCount = 0;
			auto status = ::PdhGetFormattedCounterArrayW(_counter, PDH_FMT_DOUBLE, &bufferSize, &itemCount, nullptr);
			if (status != PDH_MORE_DATA || bufferSize == 0)
				return 0.0f;

			std::vector<BYTE> buffer(bufferSize);
			auto items = reinterpret_cast<PPDH_FMT_COUNTERVALUE_ITEM_W>(buffer.data());
			status = ::PdhGetFormattedCounterArrayW(_counter, PDH_FMT_DOUBLE, &bufferSize, &itemCount, items);
			if (status != ERROR_SUCCESS)
				return 0.0f;

			double total = 0.0;
			for (DWORD i = 0; i < itemCount; i++) {
				if (items[i].FmtValue.CStatus == ERROR_SUCCESS)
					total += items[i].FmtValue.doubleValue;
			}
			if (total < 0.0)
				total = 0.0;
			if (total > 100.0)
				total = 100.0;
			return static_cast<float>(total);
		}

		~GpuUsageSampler() {
			if (_query)
				::PdhCloseQuery(_query);
		}

	private:
		void Initialize() {
			if (ERROR_SUCCESS != ::PdhOpenQueryW(nullptr, 0, &_query))
				return;

			if (ERROR_SUCCESS != ::PdhAddEnglishCounterW(_query, L"\\GPU Engine(*)\\Utilization Percentage", 0, &_counter)) {
				::PdhCloseQuery(_query);
				_query = nullptr;
				_disabled = true;
				return;
			}

			::PdhCollectQueryData(_query);
			_initialized = true;
		}

		PDH_HQUERY _query{ nullptr };
		PDH_HCOUNTER _counter{ nullptr };
		bool _initialized{ false };
		bool _disabled{ false };
	};

	class NetworkUsageSampler {
	public:
		float SampleMbps() {
			ULONG size = 0;
			if (::GetIfTable(nullptr, &size, FALSE) != ERROR_INSUFFICIENT_BUFFER || size == 0)
				return 0.0f;

			std::vector<BYTE> buffer(size);
			auto table = reinterpret_cast<MIB_IFTABLE*>(buffer.data());
			if (::GetIfTable(table, &size, FALSE) != NO_ERROR)
				return 0.0f;

			ULONGLONG totalBytes = 0;
			for (DWORD i = 0; i < table->dwNumEntries; i++) {
				const auto& row = table->table[i];
				if (row.dwType == IF_TYPE_SOFTWARE_LOOPBACK)
					continue;
				totalBytes += row.dwInOctets;
				totalBytes += row.dwOutOctets;
			}

			auto now = ::GetTickCount64();
			if (_lastTick == 0) {
				_lastTick = now;
				_lastBytes = totalBytes;
				return 0.0f;
			}

			auto elapsedMs = now - _lastTick;
			if (elapsedMs == 0)
				return _lastMbps;

			ULONGLONG deltaBytes;
			if (totalBytes >= _lastBytes) {
				deltaBytes = totalBytes - _lastBytes;
			}
			else {
				deltaBytes = totalBytes + (ULLONG_MAX - _lastBytes) + 1;
			}

			const double bytesPerSecond = (static_cast<double>(deltaBytes) * 1000.0) / static_cast<double>(elapsedMs);
			if (bytesPerSecond > 12.5e9) {
				_lastTick = now;
				_lastBytes = totalBytes;
				return _lastMbps;
			}

			_lastTick = now;
			_lastBytes = totalBytes;
			_lastMbps = static_cast<float>((bytesPerSecond * 8.0) / (1024.0 * 1024.0));
			return _lastMbps;
		}

	private:
		ULONGLONG _lastBytes{ 0 };
		ULONGLONG _lastTick{ 0 };
		float _lastMbps{ 0.0f };
	};

	float GetCpuLoad() {
		static ULONGLONG previousTotalTicks = 0;
		static ULONGLONG previousIdleTicks = 0;

		FILETIME idleTime{}, kernelTime{}, userTime{};
		if (!::GetSystemTimes(&idleTime, &kernelTime, &userTime))
			return 0.0f;

		const auto idleTicks = (static_cast<ULONGLONG>(idleTime.dwHighDateTime) << 32) | idleTime.dwLowDateTime;
		const auto totalTicks =
			(static_cast<ULONGLONG>(kernelTime.dwHighDateTime) << 32) | kernelTime.dwLowDateTime;
		const auto userTicks = (static_cast<ULONGLONG>(userTime.dwHighDateTime) << 32) | userTime.dwLowDateTime;
		const auto total = totalTicks + userTicks;

		const auto totalSinceLast = total - previousTotalTicks;
		const auto idleSinceLast = idleTicks - previousIdleTicks;
		previousTotalTicks = total;
		previousIdleTicks = idleTicks;

		if (totalSinceLast == 0)
			return 0.0f;

		auto load = 1.0f - (static_cast<float>(idleSinceLast) / static_cast<float>(totalSinceLast));
		if (load < 0.0f)
			load = 0.0f;
		if (load > 1.0f)
			load = 1.0f;
		return load * 100.0f;
	}

	std::wstring RegistryTypeToString(DWORD type) {
		switch (type) {
		case REG_SZ: return L"REG_SZ";
		case REG_EXPAND_SZ: return L"REG_EXPAND_SZ";
		case REG_BINARY: return L"REG_BINARY";
		case REG_DWORD: return L"REG_DWORD";
		case REG_MULTI_SZ: return L"REG_MULTI_SZ";
		case REG_QWORD: return L"REG_QWORD";
		default: return L"REG_UNKNOWN";
		}
	}

	std::wstring BytesToHex(const BYTE* data, DWORD size, DWORD maxBytes = 32) {
		std::wostringstream out;
		auto count = (std::min)(size, maxBytes);
		for (DWORD i = 0; i < count; i++) {
			if (i)
				out << L' ';
			out << std::hex << std::uppercase;
			out.width(2);
			out.fill(L'0');
			out << static_cast<unsigned>(data[i]);
		}
		if (size > maxBytes)
			out << L" ...";
		return out.str();
	}

	std::wstring MultiSzToText(const wchar_t* text, size_t chars) {
		std::wstring result;
		size_t index = 0;
		while (index < chars && text[index] != L'\0') {
			auto* current = text + index;
			size_t len = wcslen(current);
			if (!result.empty())
				result += L" | ";
			result.append(current, len);
			index += len + 1;
		}
		return result;
	}

	std::wstring RegDataToString(DWORD type, const BYTE* data, DWORD size) {
		if (data == nullptr || size == 0)
			return {};

		switch (type) {
		case REG_SZ:
		case REG_EXPAND_SZ:
			return std::wstring(reinterpret_cast<const wchar_t*>(data));
		case REG_MULTI_SZ:
			return MultiSzToText(reinterpret_cast<const wchar_t*>(data), size / sizeof(wchar_t));
		case REG_DWORD:
			if (size >= sizeof(DWORD)) {
				auto value = *reinterpret_cast<const DWORD*>(data);
				wchar_t buffer[64]{};
				swprintf_s(buffer, L"0x%08X (%u)", value, value);
				return buffer;
			}
			break;
		case REG_QWORD:
			if (size >= sizeof(ULONGLONG)) {
				auto value = *reinterpret_cast<const ULONGLONG*>(data);
				wchar_t buffer[64]{};
				swprintf_s(buffer, L"0x%016llX (%llu)", value, value);
				return buffer;
			}
			break;
		}

		return BytesToHex(data, size);
	}

	std::wstring RegDataToEditString(DWORD type, const BYTE* data, DWORD size) {
		if (data == nullptr || size == 0)
			return {};

		switch (type) {
		case REG_SZ:
		case REG_EXPAND_SZ:
			return std::wstring(reinterpret_cast<const wchar_t*>(data));
		case REG_DWORD:
			if (size >= sizeof(DWORD))
				return std::to_wstring(*reinterpret_cast<const DWORD*>(data));
			break;
		case REG_QWORD:
			if (size >= sizeof(ULONGLONG))
				return std::to_wstring(*reinterpret_cast<const ULONGLONG*>(data));
			break;
		}

		return {};
	}

	bool ResolveRegistryRootAndSubKey(const std::wstring& fullPath, HKEY& rootKey, std::wstring& subKey) {
		struct RootMap {
			const wchar_t* Name;
			HKEY Key;
		};

		static const RootMap roots[] = {
			{ L"HKEY_CLASSES_ROOT", HKEY_CLASSES_ROOT },
			{ L"HKEY_CURRENT_USER", HKEY_CURRENT_USER },
			{ L"HKEY_LOCAL_MACHINE", HKEY_LOCAL_MACHINE },
			{ L"HKEY_USERS", HKEY_USERS },
			{ L"HKEY_CURRENT_CONFIG", HKEY_CURRENT_CONFIG },
		};

		for (const auto& root : roots) {
			size_t len = wcslen(root.Name);
			if (_wcsnicmp(fullPath.c_str(), root.Name, len) == 0) {
				rootKey = root.Key;
				if (fullPath.size() > len + 1 && fullPath[len] == L'\\')
					subKey = fullPath.substr(len + 1);
				else
					subKey.clear();
				return true;
			}
		}
		return false;
	}
}

ServerHandler::ServerHandler() {
	_tracker.SetTrackingFlags(WinSys::ConnectionType::All);
}

bool ServerHandler::RecvAll(SOCKET sock, void* buf, int len) {
	char* ptr = (char*)buf;
	int remaining = len;
	while (remaining > 0) {
		int n = recv(sock, ptr, remaining, 0);
		if (n <= 0) return false;
		ptr += n;
		remaining -= n;
	}
	return true;
}

bool ServerHandler::SendAll(SOCKET sock, const void* buf, int len) {
	const char* ptr = (const char*)buf;
	int remaining = len;
	while (remaining > 0) {
		int n = send(sock, ptr, remaining, 0);
		if (n <= 0) return false;
		ptr += n;
		remaining -= n;
	}
	return true;
}

static const char* MessageName(uint32_t msgType) {
	switch (msgType) {
	case MSG_RESP_PING:               return "Ping";
	case MSG_RESP_PROCESSES:          return "Processes";
	case MSG_RESP_SERVICES:           return "Services";
	case MSG_RESP_CONNECTIONS:        return "Connections";
	case MSG_RESP_CALLBACKS:          return "Kernel Callbacks";
	case MSG_RESP_SSDT:               return "SSDT";
	case MSG_RESP_KERNEL_MODULES:     return "Kernel Modules";
	case MSG_RESP_PROCESS_OBJECTS:    return "Process Objects";
	case MSG_RESP_DRIVER_VERSION:     return "Driver Version";
	case MSG_RESP_MODULE_SNAPSHOT:    return "Module Snapshot";
	case MSG_RESP_MODULE_PAGES:       return "Module Pages";
	case MSG_RESP_RELEASE_SNAPSHOT:   return "Release Snapshot";
	case MSG_RESP_EPROCESS_OFFSETS:   return "EPROCESS Offsets";
	case MSG_RESP_SYSINFO:            return "System Info";
	case MSG_RESP_CROSS_CHECK:        return "Cross Check";
	case MSG_RESP_KERNEL_BASE:        return "Kernel Base";
	case MSG_RESP_PERFORMANCE:        return "Performance";
	case MSG_RESP_REGISTRY_ENUM:      return "Registry Enum";
	case MSG_RESP_GDT:                return "GDT";
	case MSG_RESP_IDT:                return "IDT";
	case MSG_RESP_WFP_FILTERS:        return "WFP Filters";
	case MSG_RESP_WFP_CALLOUTS:       return "WFP Callouts";
	case MSG_RESP_IRP_DISPATCH:       return "IRP Dispatch";
	case MSG_RESP_HANDLES:            return "Handles";
	case MSG_RESP_BIG_POOL:           return "Big Pool";
	case MSG_RESP_POOL_TAGS:          return "Pool Tags";
	case MSG_RESP_INTERRUPT_INFO:     return "Interrupt Info";
	case MSG_RESP_ETW_SESSIONS:       return "ETW Sessions";
	case MSG_RESP_ETW_PROVIDERS:      return "ETW Providers";
	case MSG_RESP_CERTIFICATES:       return "Root Certificates";
	case MSG_RESP_ADAPTERS:           return "Network Adapters";
	case MSG_RESP_RPC_ENDPOINTS:      return "RPC Endpoints";
	case MSG_RESP_NAMED_PIPES:        return "Named Pipes";
	case MSG_RESP_MINIFILTERS:        return "MiniFilters";
	case MSG_RESP_FILTER_INSTANCES:   return "Filter Instances";
	case MSG_RESP_OBJ_DIRECTORY:      return "Object Directory";
	case MSG_RESP_NTDLL_FUNCTIONS:    return "Ntdll Functions";
	case MSG_RESP_INSTRUMENTATION_CB: return "Instrumentation Callbacks";
	case MSG_RESP_DSE_STATUS:         return "DSE Status";
	case MSG_RESP_KERNEL_INTEGRITY:   return "Kernel Integrity";
	case MSG_RESP_BYOVD_SCAN:         return "BYOVD Scan";
	case MSG_RESP_MEMORY_READ:        return "Memory Read";
	case MSG_RESP_MEMORY_WRITE:       return "Memory Write";
	case MSG_RESP_CI_POLICY:          return "CI Policy";
	case MSG_RESP_HYPERVISOR_HOOKS:   return "Hypervisor Hooks";
	default:                          return "Unknown";
	}
}

bool ServerHandler::SendResponse(SOCKET sock, uint32_t msgType, uint32_t status, const void* data, uint32_t dataSize) {
	const char* name = MessageName(msgType);
	if (status == WINSYS_STATUS_OK)
		printf("    [>] %-24s | %u bytes\n", name, dataSize);
	else if (status == WINSYS_STATUS_NO_DRIVER)
		printf("    [!] %-24s | no driver\n", name);
	else
		printf("    [!] %-24s | error\n", name);

	WinSysMessageHeader header{};
	header.MessageType = msgType;
	header.DataSize = dataSize;
	header.Status = status;
	if (!SendAll(sock, &header, sizeof(header)))
		return false;
	if (dataSize > 0 && data) {
		if (!SendAll(sock, data, dataSize))
			return false;
	}
	return true;
}

void ServerHandler::HandleClient(SOCKET clientSocket) {
	while (true) {
		WinSysMessageHeader header{};
		if (!RecvAll(clientSocket, &header, sizeof(header)))
			break;

		// Read payload if any
		std::vector<uint8_t> payload;
		if (header.DataSize > 0) {
			if (header.DataSize > 64 * 1024 * 1024) // 64MB sanity limit
				break;
			payload.resize(header.DataSize);
			if (!RecvAll(clientSocket, payload.data(), header.DataSize))
				break;
		}

		switch (header.MessageType) {
		case MSG_REQ_PING:
			HandlePing(clientSocket);
			break;
		case MSG_REQ_PROCESSES:
			HandleProcesses(clientSocket);
			break;
		case MSG_REQ_SERVICES:
			HandleServices(clientSocket);
			break;
		case MSG_REQ_CONNECTIONS:
			HandleConnections(clientSocket);
			break;
		case MSG_REQ_CALLBACKS:
			HandleCallbacks(clientSocket, payload.data(), header.DataSize);
			break;
		case MSG_REQ_SSDT:
			HandleSSDT(clientSocket);
			break;
		case MSG_REQ_KERNEL_MODULES:
			HandleKernelModules(clientSocket);
			break;
		case MSG_REQ_PROCESS_OBJECTS:
			HandleProcessObjects(clientSocket);
			break;
		case MSG_REQ_DRIVER_VERSION:
			HandleDriverVersion(clientSocket);
			break;
		case MSG_REQ_MODULE_SNAPSHOT:
			HandleModuleSnapshot(clientSocket);
			break;
		case MSG_REQ_MODULE_PAGES:
			HandleModulePages(clientSocket, payload.data(), header.DataSize);
			break;
		case MSG_REQ_RELEASE_SNAPSHOT:
			HandleReleaseSnapshot(clientSocket);
			break;
		case MSG_REQ_EPROCESS_OFFSETS:
			HandleEprocessOffsets(clientSocket, payload.data(), header.DataSize);
			break;
		case MSG_REQ_SYSINFO:
			HandleSysInfo(clientSocket);
			break;
		case MSG_REQ_CROSS_CHECK:
			HandleCrossCheck(clientSocket);
			break;
		case MSG_REQ_KERNEL_BASE:
			HandleKernelBase(clientSocket);
			break;
		case MSG_REQ_PERFORMANCE:
			HandlePerformance(clientSocket);
			break;
		case MSG_REQ_REGISTRY_ENUM:
			HandleRegistryEnum(clientSocket, payload.data(), header.DataSize);
			break;
		case MSG_REQ_GDT:
			HandleGdt(clientSocket);
			break;
		case MSG_REQ_IDT:
			HandleIdt(clientSocket);
			break;
		case MSG_REQ_WFP_FILTERS:
			HandleWfpFilters(clientSocket);
			break;
		case MSG_REQ_WFP_CALLOUTS:
			HandleWfpCallouts(clientSocket);
			break;
		case MSG_REQ_IRP_DISPATCH:
			HandleIrpDispatch(clientSocket, payload.data(), header.DataSize);
			break;
		case MSG_REQ_HANDLES:
			HandleHandles(clientSocket);
			break;
		case MSG_REQ_BIG_POOL:
			HandleBigPool(clientSocket);
			break;
		case MSG_REQ_POOL_TAGS:
			HandlePoolTags(clientSocket);
			break;
		case MSG_REQ_INTERRUPT_INFO:
			HandleInterruptInfo(clientSocket);
			break;
		case MSG_REQ_ETW_SESSIONS:
			HandleEtwSessions(clientSocket);
			break;
		case MSG_REQ_ETW_PROVIDERS:
			HandleEtwProviders(clientSocket);
			break;
		case MSG_REQ_CERTIFICATES:
			HandleCertificates(clientSocket);
			break;
		case MSG_REQ_ADAPTERS:
			HandleAdapters(clientSocket);
			break;
		case MSG_REQ_RPC_ENDPOINTS:
			HandleRpcEndpoints(clientSocket);
			break;
		case MSG_REQ_NAMED_PIPES:
			HandleNamedPipes(clientSocket);
			break;
		case MSG_REQ_MINIFILTERS:
			HandleMiniFilters(clientSocket);
			break;
		case MSG_REQ_FILTER_INSTANCES:
			HandleFilterInstances(clientSocket, payload.data(), header.DataSize);
			break;
		case MSG_REQ_OBJ_DIRECTORY:
			HandleObjDirectory(clientSocket, payload.data(), header.DataSize);
			break;
		case MSG_REQ_NTDLL_FUNCTIONS:
			HandleNtdllFunctions(clientSocket);
			break;
		case MSG_REQ_INSTRUMENTATION_CB:
			HandleInstrumentationCallbacks(clientSocket);
			break;
		case MSG_REQ_DSE_STATUS:
			HandleDseStatus(clientSocket);
			break;
		case MSG_REQ_KERNEL_INTEGRITY:
			HandleKernelIntegrity(clientSocket);
			break;
		case MSG_REQ_BYOVD_SCAN:
			HandleByovdScan(clientSocket);
			break;
		case MSG_REQ_MEMORY_READ:
			HandleMemoryRead(clientSocket, payload.data(), header.DataSize);
			break;
		case MSG_REQ_MEMORY_WRITE:
			HandleMemoryWrite(clientSocket, payload.data(), header.DataSize);
			break;
		case MSG_REQ_CI_POLICY:
			HandleCiPolicy(clientSocket);
			break;
		case MSG_REQ_HYPERVISOR_HOOKS:
			HandleHypervisorHooks(clientSocket);
			break;
		default:
			// Unknown message type - send error
			SendResponse(clientSocket, header.MessageType + 0x100, WINSYS_STATUS_ERROR, nullptr, 0);
			break;
		}
	}
}

void ServerHandler::HandleSysInfo(SOCKET sock) {
	SysInfoNet info{};
	if (auto ntdll = ::GetModuleHandleW(L"ntdll.dll")) {
		using RtlGetVersionPtr = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);
		auto rtlGetVersion = reinterpret_cast<RtlGetVersionPtr>(::GetProcAddress(ntdll, "RtlGetVersion"));
		if (rtlGetVersion) {
			RTL_OSVERSIONINFOEXW versionInfo{};
			versionInfo.dwOSVersionInfoSize = sizeof(versionInfo);
			if (rtlGetVersion(reinterpret_cast<PRTL_OSVERSIONINFOW>(&versionInfo)) == 0) {
				info.MajorVersion = versionInfo.dwMajorVersion;
				info.MinorVersion = versionInfo.dwMinorVersion;
				info.BuildNumber = versionInfo.dwBuildNumber;
			}
		}
	}

	DWORD ubr = 0;
	DWORD ubrSize = sizeof(ubr);
	::RegGetValueW(HKEY_LOCAL_MACHINE,
		L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
		L"UBR",
		RRF_RT_REG_DWORD,
		nullptr,
		&ubr,
		&ubrSize);
	info.Revision = ubr;

	wchar_t displayVersion[64]{};
	DWORD displayVersionSize = sizeof(displayVersion);
	if (::RegGetValueW(HKEY_LOCAL_MACHINE,
		L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
		L"DisplayVersion",
		RRF_RT_REG_SZ,
		nullptr,
		displayVersion,
		&displayVersionSize) == ERROR_SUCCESS)
	{
		auto displayVersionUtf8 = WideToUtf8(displayVersion);
		strncpy_s(info.DisplayVersion, sizeof(info.DisplayVersion), displayVersionUtf8.c_str(), _TRUNCATE);
	}

	wchar_t productName[128]{};
	DWORD productNameSize = sizeof(productName);
	if (::RegGetValueW(HKEY_LOCAL_MACHINE,
		L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
		L"ProductName",
		RRF_RT_REG_SZ,
		nullptr,
		productName,
		&productNameSize) == ERROR_SUCCESS)
	{
		auto productNameUtf8 = WideToUtf8(productName);
		strncpy_s(info.ProductName, sizeof(info.ProductName), productNameUtf8.c_str(), _TRUNCATE);
	}

	SendResponse(sock, MSG_RESP_SYSINFO, WINSYS_STATUS_OK, &info, sizeof(info));
}

void ServerHandler::HandlePing(SOCKET sock) {
	uint32_t version = WINSYS_PROTOCOL_VERSION_NET;
	SendResponse(sock, MSG_RESP_PING, WINSYS_STATUS_OK, &version, sizeof(version));
}

void ServerHandler::HandleProcesses(SOCKET sock) {
	_pm.EnumProcesses();
	auto& processes = _pm.GetProcesses();

	std::vector<ProcessInfoNet> netProcs;
	netProcs.reserve(processes.size());

	for (auto& p : processes) {
		ProcessInfoNet np{};
		np.Id = p->Id;
		np.ParentId = p->ParentId;
		np.SessionId = p->SessionId;
		np.HandleCount = p->HandleCount;
		np.ThreadCount = p->ThreadCount;
		np.PeakThreads = p->PeakThreads;
		np.CreateTime = p->CreateTime;
		np.UserTime = p->UserTime;
		np.KernelTime = p->KernelTime;
		np.WorkingSetPrivateSize = p->WorkingSetPrivateSize;
		np.VirtualSize = (uint64_t)p->VirtualSize;
		np.PeakVirtualSize = (uint64_t)p->PeakVirtualSize;
		np.WorkingSetSize = (uint64_t)p->WorkingSetSize;
		np.PeakWorkingSetSize = (uint64_t)p->PeakWorkingSetSize;
		np.PrivatePageCount = (uint64_t)p->PrivatePageCount;
		np.PagedPoolUsage = (uint64_t)p->PagedPoolUsage;
		np.PeakPagedPoolUsage = (uint64_t)p->PeakPagedPoolUsage;
		np.NonPagedPoolUsage = (uint64_t)p->NonPagedPoolUsage;
		np.PeakNonPagedPoolUsage = (uint64_t)p->PeakNonPagedPoolUsage;
		np.PagefileUsage = (uint64_t)p->PagefileUsage;
		np.PeakPagefileUsage = (uint64_t)p->PeakPagefileUsage;
		np.CPU = p->CPU;
		np.BasePriority = p->BasePriority;
		np.PageFaultCount = p->PageFaultCount;
		np.HardFaultCount = p->HardFaultCount;

		auto name = WideToUtf8(p->GetImageName());
		strncpy_s(np.ImageName, sizeof(np.ImageName), name.c_str(), _TRUNCATE);

		auto path = WideToUtf8(p->GetNativeImagePath());
		strncpy_s(np.ImagePath, sizeof(np.ImagePath), path.c_str(), _TRUNCATE);

		netProcs.push_back(np);
	}

	uint32_t dataSize = (uint32_t)(netProcs.size() * sizeof(ProcessInfoNet));
	SendResponse(sock, MSG_RESP_PROCESSES, WINSYS_STATUS_OK, netProcs.data(), dataSize);
}

void ServerHandler::HandleServices(SOCKET sock) {
	auto services = WinSys::ServiceManager::EnumServices();

	std::vector<ServiceInfoNet> netSvcs;
	netSvcs.reserve(services.size());

	for (auto& s : services) {
		ServiceInfoNet ns{};
		auto& status = s->GetStatusProcess();
		ns.ProcessId = status.ProcessId;
		ns.Type = (uint32_t)status.Type;
		ns.CurrentState = (uint32_t)status.CurrentState;
		ns.ControlsAccepted = (uint32_t)status.ControlsAccepted;

		auto config = WinSys::ServiceManager::GetServiceConfiguration(s->GetName());
		if (config) {
			ns.StartType = (uint32_t)config->StartType;
			auto binPath = WideToUtf8(config->BinaryPathName);
			strncpy_s(ns.BinaryPath, sizeof(ns.BinaryPath), binPath.c_str(), _TRUNCATE);
		}

		auto name = WideToUtf8(std::wstring(s->GetName()));
		strncpy_s(ns.Name, sizeof(ns.Name), name.c_str(), _TRUNCATE);

		auto displayName = WideToUtf8(std::wstring(s->GetDisplayName()));
		strncpy_s(ns.DisplayName, sizeof(ns.DisplayName), displayName.c_str(), _TRUNCATE);

		netSvcs.push_back(ns);
	}

	uint32_t dataSize = (uint32_t)(netSvcs.size() * sizeof(ServiceInfoNet));
	SendResponse(sock, MSG_RESP_SERVICES, WINSYS_STATUS_OK, netSvcs.data(), dataSize);
}

void ServerHandler::HandleConnections(SOCKET sock) {
	_tracker.EnumConnections();
	auto& connections = _tracker.GetConnections();

	std::vector<ConnectionNet> netConns;
	netConns.reserve(connections.size());

	for (auto& c : connections) {
		ConnectionNet nc{};
		nc.State = (uint32_t)c->State;
		nc.Pid = c->Pid;
		nc.Type = (uint32_t)c->Type;
		nc.LocalPort = c->LocalPort;
		nc.RemotePort = c->RemotePort;

		// Copy addresses
		bool isV6 = (c->Type == WinSys::ConnectionType::TcpV6 || c->Type == WinSys::ConnectionType::UdpV6);
		if (isV6) {
			memcpy(nc.LocalAddress, c->ucLocalAddress, 16);
			memcpy(nc.RemoteAddress, c->ucRemoteAddress, 16);
		}
		else {
			memcpy(nc.LocalAddress, &c->LocalAddress, 4);
			memcpy(nc.RemoteAddress, &c->RemoteAddress, 4);
		}

		auto modName = WideToUtf8(c->ModuleName);
		strncpy_s(nc.ModuleName, sizeof(nc.ModuleName), modName.c_str(), _TRUNCATE);

		netConns.push_back(nc);
	}

	uint32_t dataSize = (uint32_t)(netConns.size() * sizeof(ConnectionNet));
	SendResponse(sock, MSG_RESP_CONNECTIONS, WINSYS_STATUS_OK, netConns.data(), dataSize);
}

void ServerHandler::HandleCallbacks(SOCKET sock, const void* payload, uint32_t size) {
	if (!DriverHelper::IsDriverLoaded()) {
		SendResponse(sock, MSG_RESP_CALLBACKS, WINSYS_STATUS_NO_DRIVER, nullptr, 0);
		return;
	}

	CALLBACK_QUERY query{};
	if (size >= sizeof(CALLBACK_QUERY))
		memcpy(&query, payload, sizeof(CALLBACK_QUERY));

	MODULE_INFO* callbacks = DriverHelper::GetCallbacks(query);
	SendResponse(sock, MSG_RESP_CALLBACKS, WINSYS_STATUS_OK, callbacks, sizeof(MODULE_INFO) * 200);
}

void ServerHandler::HandleSSDT(SOCKET sock) {
	if (!DriverHelper::IsDriverLoaded()) {
		SendResponse(sock, MSG_RESP_SSDT, WINSYS_STATUS_NO_DRIVER, nullptr, 0);
		return;
	}

	ULONG_PTR* ssdt = DriverHelper::GetSSDT();
	SendResponse(sock, MSG_RESP_SSDT, WINSYS_STATUS_OK, ssdt, sizeof(ULONG_PTR) * 500);
}

void ServerHandler::HandleKernelModules(SOCKET sock) {
	if (!DriverHelper::IsDriverLoaded()) {
		SendResponse(sock, MSG_RESP_KERNEL_MODULES, WINSYS_STATUS_NO_DRIVER, nullptr, 0);
		return;
	}

	MODULE_INFO* modules = DriverHelper::GetModules();
	SendResponse(sock, MSG_RESP_KERNEL_MODULES, WINSYS_STATUS_OK, modules, sizeof(MODULE_INFO) * 200);
}

void ServerHandler::HandleProcessObjects(SOCKET sock) {
	if (!DriverHelper::IsDriverLoaded()) {
		SendResponse(sock, MSG_RESP_PROCESS_OBJECTS, WINSYS_STATUS_NO_DRIVER, nullptr, 0);
		return;
	}

	auto objects = DriverHelper::GetProcessObjects();
	uint32_t dataSize = (uint32_t)(objects.size() * sizeof(KERNEL_PROCESS_ENTRY));
	SendResponse(sock, MSG_RESP_PROCESS_OBJECTS, WINSYS_STATUS_OK, objects.data(), dataSize);
}

void ServerHandler::HandleDriverVersion(SOCKET sock) {
	uint16_t version = DriverHelper::GetVersion();
	SendResponse(sock, MSG_RESP_DRIVER_VERSION, WINSYS_STATUS_OK, &version, sizeof(version));
}

void ServerHandler::HandleModuleSnapshot(SOCKET sock) {
	if (!DriverHelper::IsDriverLoaded()) {
		SendResponse(sock, MSG_RESP_MODULE_SNAPSHOT, WINSYS_STATUS_NO_DRIVER, nullptr, 0);
		return;
	}

	unsigned long count = 0;
	bool ok = DriverHelper::CreateModuleSnapshot(count);
	uint32_t status = ok ? WINSYS_STATUS_OK : WINSYS_STATUS_ERROR;
	SendResponse(sock, MSG_RESP_MODULE_SNAPSHOT, status, &count, sizeof(count));
}

void ServerHandler::HandleModulePages(SOCKET sock, const void* payload, uint32_t size) {
	if (!DriverHelper::IsDriverLoaded() || size < sizeof(MODULE_PAGE_REQUEST)) {
		SendResponse(sock, MSG_RESP_MODULE_PAGES, WINSYS_STATUS_NO_DRIVER, nullptr, 0);
		return;
	}

	MODULE_PAGE_REQUEST request{};
	memcpy(&request, payload, sizeof(MODULE_PAGE_REQUEST));

	if (request.Count > 4096) {
		SendResponse(sock, MSG_RESP_MODULE_PAGES, WINSYS_STATUS_ERROR, nullptr, 0);
		return;
	}

	std::vector<KERNEL_MODULE_ENTRY> entries(request.Count);
	unsigned long returnedCount = 0;
	bool ok = DriverHelper::QueryModulePage(request.StartIndex, request.Count, entries.data(), returnedCount);

	if (ok) {
		uint32_t dataSize = returnedCount * sizeof(KERNEL_MODULE_ENTRY);
		SendResponse(sock, MSG_RESP_MODULE_PAGES, WINSYS_STATUS_OK, entries.data(), dataSize);
	}
	else {
		SendResponse(sock, MSG_RESP_MODULE_PAGES, WINSYS_STATUS_ERROR, nullptr, 0);
	}
}

void ServerHandler::HandleReleaseSnapshot(SOCKET sock) {
	bool ok = DriverHelper::ReleaseModuleSnapshot();
	SendResponse(sock, MSG_RESP_RELEASE_SNAPSHOT, ok ? WINSYS_STATUS_OK : WINSYS_STATUS_ERROR, nullptr, 0);
}

void ServerHandler::HandleEprocessOffsets(SOCKET sock, const void* payload, uint32_t size) {
	if (size < sizeof(EPROCESS_OFFSETS)) {
		SendResponse(sock, MSG_RESP_EPROCESS_OFFSETS, WINSYS_STATUS_ERROR, nullptr, 0);
		return;
	}

	EPROCESS_OFFSETS offsets{};
	memcpy(&offsets, payload, sizeof(EPROCESS_OFFSETS));
	bool ok = DriverHelper::SendEprocessOffsets(offsets);
	SendResponse(sock, MSG_RESP_EPROCESS_OFFSETS, ok ? WINSYS_STATUS_OK : WINSYS_STATUS_ERROR, nullptr, 0);
}

void ServerHandler::HandleCrossCheck(SOCKET sock) {
	if (!DriverHelper::IsDriverLoaded()) {
		SendResponse(sock, MSG_RESP_CROSS_CHECK, WINSYS_STATUS_NO_DRIVER, nullptr, 0);
		return;
	}

	std::vector<BYTE> buffer;
	DWORD bytes = 0;
	if (!DriverHelper::CrossCheckProcesses(buffer, bytes)) {
		SendResponse(sock, MSG_RESP_CROSS_CHECK, WINSYS_STATUS_ERROR, nullptr, 0);
		return;
	}

	SendResponse(sock, MSG_RESP_CROSS_CHECK, WINSYS_STATUS_OK, buffer.data(), bytes);
}

void ServerHandler::HandleKernelBase(SOCKET sock) {
	KernelBaseInfoNet info{};

	LPVOID drivers[1024]{};
	DWORD cbNeeded = 0;
	if (!::EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) || cbNeeded < sizeof(LPVOID) || drivers[0] == nullptr) {
		SendResponse(sock, MSG_RESP_KERNEL_BASE, WINSYS_STATUS_ERROR, nullptr, 0);
		return;
	}

	info.KernelBase = reinterpret_cast<uint64_t>(drivers[0]);

	// Get ntoskrnl file path and extract PE/PDB info
	wchar_t driverPath[MAX_PATH]{};
	if (!::GetDeviceDriverFileNameW(drivers[0], driverPath, _countof(driverPath))) {
		SendResponse(sock, MSG_RESP_KERNEL_BASE, WINSYS_STATUS_ERROR, nullptr, 0);
		return;
	}

	// Normalize path
	std::wstring path(driverPath);
	if (path.rfind(L"\\SystemRoot\\", 0) == 0) {
		wchar_t winDir[MAX_PATH]{};
		::GetWindowsDirectoryW(winDir, MAX_PATH);
		path = std::wstring(winDir) + path.substr(11);
	}
	else if (path.rfind(L"\\??\\", 0) == 0) {
		path = path.substr(4);
	}

	// Map the PE to extract image size and PDB debug info
	HANDLE hFile = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hFile == INVALID_HANDLE_VALUE) {
		SendResponse(sock, MSG_RESP_KERNEL_BASE, WINSYS_STATUS_ERROR, nullptr, 0);
		return;
	}
	HANDLE hMapping = ::CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
	if (!hMapping) {
		::CloseHandle(hFile);
		SendResponse(sock, MSG_RESP_KERNEL_BASE, WINSYS_STATUS_ERROR, nullptr, 0);
		return;
	}
	auto* base = static_cast<BYTE*>(::MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0));
	if (!base) {
		::CloseHandle(hMapping);
		::CloseHandle(hFile);
		SendResponse(sock, MSG_RESP_KERNEL_BASE, WINSYS_STATUS_ERROR, nullptr, 0);
		return;
	}

	auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
	if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
		auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
		if (nt->Signature == IMAGE_NT_SIGNATURE) {
			info.ImageSize = nt->OptionalHeader.SizeOfImage;

			DWORD debugDirRVA = 0, debugDirSize = 0;
			if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
				auto* opt64 = reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(&nt->OptionalHeader);
				debugDirRVA = opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
				debugDirSize = opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
			}
			else {
				auto* opt32 = reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(&nt->OptionalHeader);
				debugDirRVA = opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
				debugDirSize = opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
			}

			if (debugDirRVA && debugDirSize) {
				auto* section = IMAGE_FIRST_SECTION(nt);
				DWORD debugDirFileOffset = 0;
				for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
					if (debugDirRVA >= section[i].VirtualAddress &&
						debugDirRVA < section[i].VirtualAddress + section[i].Misc.VirtualSize) {
						debugDirFileOffset = debugDirRVA - section[i].VirtualAddress + section[i].PointerToRawData;
						break;
					}
				}

				if (debugDirFileOffset) {
					DWORD numEntries = debugDirSize / sizeof(IMAGE_DEBUG_DIRECTORY);
					auto* debugDir = reinterpret_cast<IMAGE_DEBUG_DIRECTORY*>(base + debugDirFileOffset);
					for (DWORD i = 0; i < numEntries; i++) {
						if (debugDir[i].Type == IMAGE_DEBUG_TYPE_CODEVIEW && debugDir[i].SizeOfData >= 24) {
							struct CV_INFO_PDB70 {
								DWORD CvSignature;
								GUID  Signature;
								DWORD Age;
								char  PdbFileName[1];
							};
							auto* cv = reinterpret_cast<CV_INFO_PDB70*>(base + debugDir[i].PointerToRawData);
							if (cv->CvSignature == 'SDSR') { // RSDS
								memcpy(info.PdbGuid, &cv->Signature, 16);
								info.PdbAge = cv->Age;
								strncpy_s(info.PdbFileName, sizeof(info.PdbFileName), cv->PdbFileName, _TRUNCATE);
								break;
							}
						}
					}
				}
			}
		}
	}

	::UnmapViewOfFile(base);
	::CloseHandle(hMapping);
	::CloseHandle(hFile);

	SendResponse(sock, MSG_RESP_KERNEL_BASE, WINSYS_STATUS_OK, &info, sizeof(info));
}

void ServerHandler::HandlePerformance(SOCKET sock) {
	static GpuUsageSampler gpuSampler;
	static NetworkUsageSampler networkSampler;
	static std::string cpuName = GetCpuName();
	static std::string gpuName = GetGpuName();

	PerformanceSnapshotNet snapshot{};
	snapshot.CpuUsage = GetCpuLoad();

	MEMORYSTATUSEX statex{};
	statex.dwLength = sizeof(statex);
	if (::GlobalMemoryStatusEx(&statex)) {
		snapshot.MemoryUsage = static_cast<float>(statex.dwMemoryLoad);
		snapshot.TotalPhysicalBytes = statex.ullTotalPhys;
	}

	snapshot.GpuUsage = gpuSampler.Sample();
	snapshot.NetworkMbps = networkSampler.SampleMbps();
	snapshot.UptimeSeconds = ::GetTickCount64() / 1000;
	strncpy_s(snapshot.CpuName, sizeof(snapshot.CpuName), cpuName.c_str(), _TRUNCATE);
	strncpy_s(snapshot.GpuName, sizeof(snapshot.GpuName), gpuName.c_str(), _TRUNCATE);

	SendResponse(sock, MSG_RESP_PERFORMANCE, WINSYS_STATUS_OK, &snapshot, sizeof(snapshot));
}

void ServerHandler::HandleRegistryEnum(SOCKET sock, const void* payload, uint32_t size) {
	if (size < sizeof(RegistryEnumRequestNet)) {
		SendResponse(sock, MSG_RESP_REGISTRY_ENUM, WINSYS_STATUS_ERROR, nullptr, 0);
		return;
	}

	const auto& request = *reinterpret_cast<const RegistryEnumRequestNet*>(payload);
	auto fullPath = Utf8ToWide(request.Path);
	HKEY rootKey = nullptr;
	std::wstring subKey;
	if (!ResolveRegistryRootAndSubKey(fullPath, rootKey, subKey)) {
		SendResponse(sock, MSG_RESP_REGISTRY_ENUM, WINSYS_STATUS_ERROR, nullptr, 0);
		return;
	}

	HKEY openedKey = nullptr;
	if (::RegOpenKeyExW(rootKey, subKey.empty() ? nullptr : subKey.c_str(), 0, KEY_READ, &openedKey) != ERROR_SUCCESS) {
		SendResponse(sock, MSG_RESP_REGISTRY_ENUM, WINSYS_STATUS_ERROR, nullptr, 0);
		return;
	}

	if (request.QueryType == 1) {
		DWORD subKeyCount = 0, maxSubKeyLen = 0;
		if (::RegQueryInfoKeyW(openedKey, nullptr, nullptr, nullptr, &subKeyCount, &maxSubKeyLen, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
			::RegCloseKey(openedKey);
			SendResponse(sock, MSG_RESP_REGISTRY_ENUM, WINSYS_STATUS_ERROR, nullptr, 0);
			return;
		}

		std::vector<RegistryKeyNet> keys;
		keys.reserve(subKeyCount);
		std::vector<wchar_t> name(maxSubKeyLen + 1);
		for (DWORD index = 0; index < subKeyCount; index++) {
			DWORD chars = static_cast<DWORD>(name.size());
			if (::RegEnumKeyExW(openedKey, index, name.data(), &chars, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
				continue;

			RegistryKeyNet key{};
			auto utf8 = WideToUtf8(std::wstring(name.data(), chars));
			strncpy_s(key.Name, sizeof(key.Name), utf8.c_str(), _TRUNCATE);
			keys.push_back(key);
		}
		::RegCloseKey(openedKey);
		SendResponse(sock, MSG_RESP_REGISTRY_ENUM, WINSYS_STATUS_OK, keys.data(), static_cast<uint32_t>(keys.size() * sizeof(RegistryKeyNet)));
		return;
	}

	if (request.QueryType == 2) {
		DWORD valueCount = 0, maxValueNameLen = 0, maxValueDataLen = 0;
		if (::RegQueryInfoKeyW(openedKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &valueCount, &maxValueNameLen, &maxValueDataLen, nullptr, nullptr) != ERROR_SUCCESS) {
			::RegCloseKey(openedKey);
			SendResponse(sock, MSG_RESP_REGISTRY_ENUM, WINSYS_STATUS_ERROR, nullptr, 0);
			return;
		}

		std::vector<RegistryValueNet> values;
		values.reserve(valueCount);
		std::vector<wchar_t> valueName(maxValueNameLen + 2);
		std::vector<BYTE> data(maxValueDataLen + sizeof(wchar_t) * 2);
		for (DWORD index = 0; index < valueCount; index++) {
			DWORD nameChars = static_cast<DWORD>(valueName.size());
			DWORD dataBytes = static_cast<DWORD>(data.size());
			DWORD type = 0;
			if (::RegEnumValueW(openedKey, index, valueName.data(), &nameChars, nullptr, &type, data.data(), &dataBytes) != ERROR_SUCCESS)
				continue;

			RegistryValueNet value{};
			value.Type = type;
			value.IsDefault = nameChars == 0 ? 1u : 0u;
			value.DataSize = (std::min)(dataBytes, (DWORD)sizeof(value.Data));
			auto displayName = value.IsDefault ? std::string("(Default)") : WideToUtf8(std::wstring(valueName.data(), nameChars));
			strncpy_s(value.Name, sizeof(value.Name), displayName.c_str(), _TRUNCATE);
			if (value.DataSize > 0)
				memcpy(value.Data, data.data(), value.DataSize);
			values.push_back(value);
		}
		::RegCloseKey(openedKey);
		SendResponse(sock, MSG_RESP_REGISTRY_ENUM, WINSYS_STATUS_OK, values.data(), static_cast<uint32_t>(values.size() * sizeof(RegistryValueNet)));
		return;
	}

	::RegCloseKey(openedKey);
	SendResponse(sock, MSG_RESP_REGISTRY_ENUM, WINSYS_STATUS_ERROR, nullptr, 0);
}

// === Driver-based kernel handlers ===

void ServerHandler::HandleGdt(SOCKET sock) {
	if (!DriverHelper::IsDriverLoaded()) {
		SendResponse(sock, MSG_RESP_GDT, WINSYS_STATUS_NO_DRIVER, nullptr, 0);
		return;
	}
	GDT_INFO info{};
	if (DriverHelper::GetGdt(info))
		SendResponse(sock, MSG_RESP_GDT, WINSYS_STATUS_OK, &info, sizeof(info));
	else
		SendResponse(sock, MSG_RESP_GDT, WINSYS_STATUS_ERROR, nullptr, 0);
}

void ServerHandler::HandleIdt(SOCKET sock) {
	if (!DriverHelper::IsDriverLoaded()) {
		SendResponse(sock, MSG_RESP_IDT, WINSYS_STATUS_NO_DRIVER, nullptr, 0);
		return;
	}
	IDT_INFO info{};
	if (DriverHelper::GetIdt(info))
		SendResponse(sock, MSG_RESP_IDT, WINSYS_STATUS_OK, &info, sizeof(info));
	else
		SendResponse(sock, MSG_RESP_IDT, WINSYS_STATUS_ERROR, nullptr, 0);
}

void ServerHandler::HandleWfpFilters(SOCKET sock) {
	if (!DriverHelper::IsDriverLoaded()) {
		SendResponse(sock, MSG_RESP_WFP_FILTERS, WINSYS_STATUS_NO_DRIVER, nullptr, 0);
		return;
	}
	std::vector<WFP_FILTER_ENTRY> entries;
	if (DriverHelper::EnumWfpFilters(entries))
		SendResponse(sock, MSG_RESP_WFP_FILTERS, WINSYS_STATUS_OK, entries.data(), static_cast<uint32_t>(entries.size() * sizeof(WFP_FILTER_ENTRY)));
	else
		SendResponse(sock, MSG_RESP_WFP_FILTERS, WINSYS_STATUS_ERROR, nullptr, 0);
}

void ServerHandler::HandleWfpCallouts(SOCKET sock) {
	if (!DriverHelper::IsDriverLoaded()) {
		SendResponse(sock, MSG_RESP_WFP_CALLOUTS, WINSYS_STATUS_NO_DRIVER, nullptr, 0);
		return;
	}
	std::vector<WFP_CALLOUT_ENTRY> entries;
	if (DriverHelper::EnumWfpCallouts(entries))
		SendResponse(sock, MSG_RESP_WFP_CALLOUTS, WINSYS_STATUS_OK, entries.data(), static_cast<uint32_t>(entries.size() * sizeof(WFP_CALLOUT_ENTRY)));
	else
		SendResponse(sock, MSG_RESP_WFP_CALLOUTS, WINSYS_STATUS_ERROR, nullptr, 0);
}

void ServerHandler::HandleIrpDispatch(SOCKET sock, const void* payload, uint32_t size) {
	if (!DriverHelper::IsDriverLoaded()) {
		SendResponse(sock, MSG_RESP_IRP_DISPATCH, WINSYS_STATUS_NO_DRIVER, nullptr, 0);
		return;
	}
	if (size < sizeof(IrpDispatchRequestNet)) {
		SendResponse(sock, MSG_RESP_IRP_DISPATCH, WINSYS_STATUS_ERROR, nullptr, 0);
		return;
	}
	auto* req = (const IrpDispatchRequestNet*)payload;
	auto driverNameW = Utf8ToWide(req->DriverName);
	IRP_DISPATCH_RESULT result{};
	if (DriverHelper::GetIrpDispatch(driverNameW.c_str(), result))
		SendResponse(sock, MSG_RESP_IRP_DISPATCH, WINSYS_STATUS_OK, &result, sizeof(result));
	else
		SendResponse(sock, MSG_RESP_IRP_DISPATCH, WINSYS_STATUS_ERROR, nullptr, 0);
}

// === NtQuerySystemInformation-based handlers ===

void ServerHandler::HandleHandles(SOCKET sock) {
	ULONG bufferSize = 1024 * 1024;
	std::vector<BYTE> buffer;
	NTSTATUS status;
	for (int i = 0; i < 8; i++) {
		buffer.resize(bufferSize);
		status = ::NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)64 /*SystemExtendedHandleInformation*/,
			buffer.data(), bufferSize, nullptr);
		if (status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL)
			bufferSize *= 2;
		else
			break;
	}
	if (status != 0) {
		SendResponse(sock, MSG_RESP_HANDLES, WINSYS_STATUS_ERROR, nullptr, 0);
		return;
	}

	struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
		PVOID Object;
		ULONG_PTR UniqueProcessId;
		ULONG_PTR HandleValue;
		ULONG GrantedAccess;
		USHORT CreatorBackTraceIndex;
		USHORT ObjectTypeIndex;
		ULONG HandleAttributes;
		ULONG Reserved;
	};
	struct SYSTEM_HANDLE_INFORMATION_EX_HDR {
		ULONG_PTR NumberOfHandles;
		ULONG_PTR Reserved;
	};

	auto* hdr = (SYSTEM_HANDLE_INFORMATION_EX_HDR*)buffer.data();
	auto* entries = (SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX*)(buffer.data() + sizeof(SYSTEM_HANDLE_INFORMATION_EX_HDR));
	size_t count = hdr->NumberOfHandles;

	std::vector<HandleEntryNet> netEntries;
	netEntries.reserve(count);
	for (size_t i = 0; i < count; i++) {
		HandleEntryNet ne{};
		ne.ProcessId = entries[i].UniqueProcessId;
		ne.HandleValue = static_cast<uint16_t>(entries[i].HandleValue);
		ne.Object = reinterpret_cast<uint64_t>(entries[i].Object);
		ne.GrantedAccess = entries[i].GrantedAccess;
		ne.ObjectTypeIndex = static_cast<uint8_t>(entries[i].ObjectTypeIndex);
		ne.Attributes = static_cast<uint16_t>(entries[i].HandleAttributes);
		netEntries.push_back(ne);
	}
	SendResponse(sock, MSG_RESP_HANDLES, WINSYS_STATUS_OK, netEntries.data(), static_cast<uint32_t>(netEntries.size() * sizeof(HandleEntryNet)));
}

void ServerHandler::HandleBigPool(SOCKET sock) {
	ULONG bufferSize = 64 * 1024;
	std::vector<BYTE> buffer;
	NTSTATUS status;
	for (int i = 0; i < 8; i++) {
		buffer.resize(bufferSize);
		status = ::NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0x42 /*SystemBigPoolInformation*/,
			buffer.data(), bufferSize, nullptr);
		if (status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL)
			bufferSize *= 2;
		else
			break;
	}
	if (status != 0) {
		SendResponse(sock, MSG_RESP_BIG_POOL, WINSYS_STATUS_ERROR, nullptr, 0);
		return;
	}

	struct SYSTEM_BIGPOOL_ENTRY {
		union { PVOID VirtualAddress; ULONG_PTR Flags; };
		SIZE_T SizeInBytes;
		union { UCHAR Tag[4]; ULONG TagUlong; };
	};
	struct SYSTEM_BIGPOOL_INFORMATION {
		ULONG Count;
		SYSTEM_BIGPOOL_ENTRY AllocatedInfo[1];
	};

	auto* info = (SYSTEM_BIGPOOL_INFORMATION*)buffer.data();
	std::vector<BigPoolEntryNet> netEntries;
	netEntries.reserve(info->Count);
	for (ULONG i = 0; i < info->Count; i++) {
		auto& e = info->AllocatedInfo[i];
		BigPoolEntryNet ne{};
		ne.VirtualAddress = (uint64_t)e.Flags & ~1ULL;
		ne.SizeInBytes = e.SizeInBytes;
		ne.Tag[0] = e.Tag[0]; ne.Tag[1] = e.Tag[1]; ne.Tag[2] = e.Tag[2]; ne.Tag[3] = e.Tag[3]; ne.Tag[4] = 0;
		ne.NonPaged = (e.Flags & 1) ? 1 : 0;
		netEntries.push_back(ne);
	}
	SendResponse(sock, MSG_RESP_BIG_POOL, WINSYS_STATUS_OK, netEntries.data(), static_cast<uint32_t>(netEntries.size() * sizeof(BigPoolEntryNet)));
}

void ServerHandler::HandlePoolTags(SOCKET sock) {
	ULONG bufferSize = 64 * 1024;
	std::vector<BYTE> buffer;
	NTSTATUS status;
	for (int i = 0; i < 8; i++) {
		buffer.resize(bufferSize);
		status = ::NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0x16 /*SystemPoolTagInformation*/,
			buffer.data(), bufferSize, nullptr);
		if (status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL)
			bufferSize *= 2;
		else
			break;
	}
	if (status != 0) {
		SendResponse(sock, MSG_RESP_POOL_TAGS, WINSYS_STATUS_ERROR, nullptr, 0);
		return;
	}

	struct SYSTEM_POOLTAG {
		union { UCHAR Tag[4]; ULONG TagUlong; };
		ULONG PagedAllocs; ULONG PagedFrees; SIZE_T PagedUsed;
		ULONG NonPagedAllocs; ULONG NonPagedFrees; SIZE_T NonPagedUsed;
	};
	struct SYSTEM_POOLTAG_INFORMATION {
		ULONG Count;
		SYSTEM_POOLTAG TagInfo[1];
	};

	auto* info = (SYSTEM_POOLTAG_INFORMATION*)buffer.data();
	std::vector<PoolTagEntryNet> netEntries;
	netEntries.reserve(info->Count);
	for (ULONG i = 0; i < info->Count; i++) {
		auto& t = info->TagInfo[i];
		PoolTagEntryNet ne{};
		ne.Tag[0] = t.Tag[0]; ne.Tag[1] = t.Tag[1]; ne.Tag[2] = t.Tag[2]; ne.Tag[3] = t.Tag[3]; ne.Tag[4] = 0;
		ne.PagedAllocs = t.PagedAllocs; ne.PagedFrees = t.PagedFrees; ne.PagedUsed = t.PagedUsed;
		ne.NonPagedAllocs = t.NonPagedAllocs; ne.NonPagedFrees = t.NonPagedFrees; ne.NonPagedUsed = t.NonPagedUsed;
		netEntries.push_back(ne);
	}
	SendResponse(sock, MSG_RESP_POOL_TAGS, WINSYS_STATUS_OK, netEntries.data(), static_cast<uint32_t>(netEntries.size() * sizeof(PoolTagEntryNet)));
}

void ServerHandler::HandleInterruptInfo(SOCKET sock) {
	SYSTEM_INFO si{};
	::GetSystemInfo(&si);
	DWORD cpuCount = si.dwNumberOfProcessors;

	struct SYSTEM_INTERRUPT_INFO_ENTRY {
		ULONG ContextSwitches; ULONG DpcCount; ULONG DpcRate;
		ULONG TimeIncrement; ULONG DpcBypassCount; ULONG ApcBypassCount;
	};

	ULONG bufSize = cpuCount * sizeof(SYSTEM_INTERRUPT_INFO_ENTRY);
	std::vector<BYTE> buffer(bufSize, 0);
	NTSTATUS status = ::NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0x17 /*SystemInterruptInformation*/,
		buffer.data(), bufSize, nullptr);
	if (status != 0) {
		SendResponse(sock, MSG_RESP_INTERRUPT_INFO, WINSYS_STATUS_ERROR, nullptr, 0);
		return;
	}

	auto* entries = (SYSTEM_INTERRUPT_INFO_ENTRY*)buffer.data();
	std::vector<InterruptInfoNet> netEntries;
	netEntries.reserve(cpuCount);
	for (DWORD i = 0; i < cpuCount; i++) {
		InterruptInfoNet ne{};
		ne.ContextSwitches = entries[i].ContextSwitches;
		ne.DpcCount = entries[i].DpcCount;
		ne.DpcRate = entries[i].DpcRate;
		ne.TimeIncrement = entries[i].TimeIncrement;
		ne.DpcBypassCount = entries[i].DpcBypassCount;
		ne.ApcBypassCount = entries[i].ApcBypassCount;
		netEntries.push_back(ne);
	}
	SendResponse(sock, MSG_RESP_INTERRUPT_INFO, WINSYS_STATUS_OK, netEntries.data(), static_cast<uint32_t>(netEntries.size() * sizeof(InterruptInfoNet)));
}

// === User-mode system handlers ===

void ServerHandler::HandleEtwSessions(SOCKET sock) {
	EVENT_TRACE_PROPERTIES* sessions[64]{};
	BYTE buffers[64][sizeof(EVENT_TRACE_PROPERTIES) + 1024]{};
	for (int i = 0; i < 64; i++) {
		sessions[i] = (EVENT_TRACE_PROPERTIES*)buffers[i];
		sessions[i]->Wnode.BufferSize = sizeof(EVENT_TRACE_PROPERTIES) + 1024;
		sessions[i]->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
	}
	ULONG count = 0;
	if (::QueryAllTracesW((PEVENT_TRACE_PROPERTIES*)sessions, 64, &count) != ERROR_SUCCESS) {
		SendResponse(sock, MSG_RESP_ETW_SESSIONS, WINSYS_STATUS_ERROR, nullptr, 0);
		return;
	}
	std::vector<EtwSessionNet> netEntries;
	for (ULONG i = 0; i < count; i++) {
		EtwSessionNet ne{};
		auto* name = (wchar_t*)((BYTE*)sessions[i] + sessions[i]->LoggerNameOffset);
		auto nameUtf8 = WideToUtf8(name);
		strncpy_s(ne.Name, sizeof(ne.Name), nameUtf8.c_str(), _TRUNCATE);
		ne.BufferSize = sessions[i]->BufferSize;
		ne.BuffersWritten = sessions[i]->BuffersWritten;
		ne.EventsLost = sessions[i]->EventsLost;
		ne.LogFileMode = sessions[i]->LogFileMode;
		netEntries.push_back(ne);
	}
	SendResponse(sock, MSG_RESP_ETW_SESSIONS, WINSYS_STATUS_OK, netEntries.data(), static_cast<uint32_t>(netEntries.size() * sizeof(EtwSessionNet)));
}

void ServerHandler::HandleEtwProviders(SOCKET sock) {
	ULONG bufSize = 0;
	::TdhEnumerateProviders(nullptr, &bufSize);
	if (bufSize == 0) {
		SendResponse(sock, MSG_RESP_ETW_PROVIDERS, WINSYS_STATUS_ERROR, nullptr, 0);
		return;
	}
	std::vector<BYTE> buffer(bufSize);
	if (::TdhEnumerateProviders((PPROVIDER_ENUMERATION_INFO)buffer.data(), &bufSize) != ERROR_SUCCESS) {
		SendResponse(sock, MSG_RESP_ETW_PROVIDERS, WINSYS_STATUS_ERROR, nullptr, 0);
		return;
	}
	auto* info = (PPROVIDER_ENUMERATION_INFO)buffer.data();
	std::vector<EtwProviderNet> netEntries;
	netEntries.reserve(info->NumberOfProviders);
	for (ULONG i = 0; i < info->NumberOfProviders; i++) {
		auto& p = info->TraceProviderInfoArray[i];
		EtwProviderNet ne{};
		auto* name = (wchar_t*)(buffer.data() + p.ProviderNameOffset);
		auto nameUtf8 = WideToUtf8(name);
		strncpy_s(ne.Name, sizeof(ne.Name), nameUtf8.c_str(), _TRUNCATE);
		wchar_t guidStr[40]{};
		::StringFromGUID2(p.ProviderGuid, guidStr, 40);
		auto guidUtf8 = WideToUtf8(guidStr);
		strncpy_s(ne.Guid, sizeof(ne.Guid), guidUtf8.c_str(), _TRUNCATE);
		netEntries.push_back(ne);
	}
	SendResponse(sock, MSG_RESP_ETW_PROVIDERS, WINSYS_STATUS_OK, netEntries.data(), static_cast<uint32_t>(netEntries.size() * sizeof(EtwProviderNet)));
}

void ServerHandler::HandleCertificates(SOCKET sock) {
	std::vector<CertificateNet> netEntries;
	const struct { DWORD flags; const char* store; } stores[] = {
		{ CERT_SYSTEM_STORE_LOCAL_MACHINE, "Local Machine" },
		{ CERT_SYSTEM_STORE_CURRENT_USER, "Current User" },
	};
	for (auto& s : stores) {
		HCERTSTORE hStore = ::CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, s.flags | CERT_STORE_READONLY_FLAG, L"ROOT");
		if (!hStore) continue;
		PCCERT_CONTEXT ctx = nullptr;
		while ((ctx = ::CertEnumCertificatesInStore(hStore, ctx)) != nullptr) {
			CertificateNet ne{};
			wchar_t subject[256]{}, issuer[256]{};
			::CertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, subject, 256);
			::CertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, nullptr, issuer, 256);
			strncpy_s(ne.Subject, sizeof(ne.Subject), WideToUtf8(subject).c_str(), _TRUNCATE);
			strncpy_s(ne.Issuer, sizeof(ne.Issuer), WideToUtf8(issuer).c_str(), _TRUNCATE);
			strncpy_s(ne.Store, sizeof(ne.Store), s.store, _TRUNCATE);
			SYSTEMTIME st{};
			::FileTimeToSystemTime(&ctx->pCertInfo->NotAfter, &st);
			sprintf_s(ne.Expires, "%04d-%02d-%02d", st.wYear, st.wMonth, st.wDay);
			BYTE hash[20]{}; DWORD hashSize = 20;
			if (::CertGetCertificateContextProperty(ctx, CERT_SHA1_HASH_PROP_ID, hash, &hashSize)) {
				char thumb[64]{};
				for (DWORD i = 0; i < hashSize; i++)
					sprintf_s(thumb + i * 3, sizeof(thumb) - i * 3, i ? ":%02X" : "%02X", hash[i]);
				strncpy_s(ne.Thumbprint, sizeof(ne.Thumbprint), thumb, _TRUNCATE);
			}
			netEntries.push_back(ne);
		}
		::CertCloseStore(hStore, 0);
	}
	SendResponse(sock, MSG_RESP_CERTIFICATES, WINSYS_STATUS_OK, netEntries.data(), static_cast<uint32_t>(netEntries.size() * sizeof(CertificateNet)));
}

void ServerHandler::HandleAdapters(SOCKET sock) {
	ULONG bufSize = 0;
	::GetAdaptersInfo(nullptr, &bufSize);
	std::vector<BYTE> buffer(bufSize);
	if (::GetAdaptersInfo((PIP_ADAPTER_INFO)buffer.data(), &bufSize) != NO_ERROR) {
		SendResponse(sock, MSG_RESP_ADAPTERS, WINSYS_STATUS_ERROR, nullptr, 0);
		return;
	}
	std::vector<AdapterInfoNet> netEntries;
	for (auto* adapter = (PIP_ADAPTER_INFO)buffer.data(); adapter; adapter = adapter->Next) {
		AdapterInfoNet ne{};
		strncpy_s(ne.Name, sizeof(ne.Name), adapter->AdapterName, _TRUNCATE);
		strncpy_s(ne.Description, sizeof(ne.Description), adapter->Description, _TRUNCATE);
		const char* typeStr = "Other";
		switch (adapter->Type) {
		case MIB_IF_TYPE_ETHERNET: typeStr = "Ethernet"; break;
		case IF_TYPE_IEEE80211: typeStr = "Wi-Fi"; break;
		case MIB_IF_TYPE_LOOPBACK: typeStr = "Loopback"; break;
		case MIB_IF_TYPE_PPP: typeStr = "PPP"; break;
		case MIB_IF_TYPE_SLIP: typeStr = "SLIP"; break;
		}
		strncpy_s(ne.Type, sizeof(ne.Type), typeStr, _TRUNCATE);
		strncpy_s(ne.Status, sizeof(ne.Status), adapter->DhcpEnabled ? "DHCP" : "Static", _TRUNCATE);
		char mac[20]{};
		sprintf_s(mac, "%02X-%02X-%02X-%02X-%02X-%02X",
			adapter->Address[0], adapter->Address[1], adapter->Address[2],
			adapter->Address[3], adapter->Address[4], adapter->Address[5]);
		strncpy_s(ne.Mac, sizeof(ne.Mac), mac, _TRUNCATE);
		strncpy_s(ne.IpAddress, sizeof(ne.IpAddress), adapter->IpAddressList.IpAddress.String, _TRUNCATE);
		strncpy_s(ne.Gateway, sizeof(ne.Gateway), adapter->GatewayList.IpAddress.String, _TRUNCATE);
		netEntries.push_back(ne);
	}
	SendResponse(sock, MSG_RESP_ADAPTERS, WINSYS_STATUS_OK, netEntries.data(), static_cast<uint32_t>(netEntries.size() * sizeof(AdapterInfoNet)));
}

void ServerHandler::HandleRpcEndpoints(SOCKET sock) {
	std::vector<RpcEndpointNet> netEntries;
	RPC_EP_INQ_HANDLE inquiry = nullptr;
	RPC_STATUS rpcStatus = ::RpcMgmtEpEltInqBegin(nullptr, RPC_C_EP_ALL_ELTS, nullptr, 0, nullptr, &inquiry);
	if (rpcStatus == RPC_S_OK && inquiry) {
		RPC_IF_ID ifId{};
		RPC_BINDING_HANDLE binding = nullptr;
		unsigned short* annotation = nullptr;
		while (::RpcMgmtEpEltInqNext(inquiry, &ifId, &binding, nullptr, &annotation) == RPC_S_OK) {
			RpcEndpointNet ne{};
			wchar_t guidStr[40]{};
			::StringFromGUID2(ifId.Uuid, guidStr, 40);
			strncpy_s(ne.InterfaceId, sizeof(ne.InterfaceId), WideToUtf8(guidStr).c_str(), _TRUNCATE);
			ne.MajorVersion = ifId.VersMajor;
			ne.MinorVersion = ifId.VersMinor;
			if (binding) {
				RPC_WSTR bindingStr = nullptr;
				if (::RpcBindingToStringBindingW(binding, &bindingStr) == RPC_S_OK) {
					strncpy_s(ne.Binding, sizeof(ne.Binding), WideToUtf8((wchar_t*)bindingStr).c_str(), _TRUNCATE);
					::RpcStringFreeW(&bindingStr);
				}
			}
			if (annotation) {
				strncpy_s(ne.Annotation, sizeof(ne.Annotation), WideToUtf8((wchar_t*)annotation).c_str(), _TRUNCATE);
				::RpcStringFreeW(&annotation);
			}
			netEntries.push_back(ne);
		}
		::RpcMgmtEpEltInqDone(&inquiry);
	}
	SendResponse(sock, MSG_RESP_RPC_ENDPOINTS, WINSYS_STATUS_OK, netEntries.data(), static_cast<uint32_t>(netEntries.size() * sizeof(RpcEndpointNet)));
}

void ServerHandler::HandleNamedPipes(SOCKET sock) {
	std::vector<NamedPipeNet> netEntries;
	WIN32_FIND_DATAW fd{};
	HANDLE hFind = ::FindFirstFileW(L"\\\\.\\pipe\\*", &fd);
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			NamedPipeNet ne{};
			strncpy_s(ne.Name, sizeof(ne.Name), WideToUtf8(fd.cFileName).c_str(), _TRUNCATE);
			netEntries.push_back(ne);
		} while (::FindNextFileW(hFind, &fd));
		::FindClose(hFind);
	}
	SendResponse(sock, MSG_RESP_NAMED_PIPES, WINSYS_STATUS_OK, netEntries.data(), static_cast<uint32_t>(netEntries.size() * sizeof(NamedPipeNet)));
}

void ServerHandler::HandleMiniFilters(SOCKET sock) {
	std::vector<MiniFilterNet> netEntries;
	BYTE buf[4096]{};
	HANDLE hFind = INVALID_HANDLE_VALUE;
	DWORD bytesReturned = 0;
	HRESULT hr = ::FilterFindFirst(FilterAggregateStandardInformation, buf, sizeof(buf), &bytesReturned, &hFind);
	while (SUCCEEDED(hr)) {
		auto* info = (PFILTER_AGGREGATE_STANDARD_INFORMATION)buf;
		MiniFilterNet ne{};
		if (info->Flags & FLTFL_ASI_IS_MINIFILTER) {
			auto& mf = info->Type.MiniFilter;
			auto* name = (wchar_t*)((BYTE*)info + mf.FilterNameBufferOffset);
			std::wstring filterName(name, mf.FilterNameLength / sizeof(wchar_t));
			strncpy_s(ne.Name, sizeof(ne.Name), WideToUtf8(filterName).c_str(), _TRUNCATE);
			auto* alt = (wchar_t*)((BYTE*)info + mf.FilterAltitudeBufferOffset);
			std::wstring altitude(alt, mf.FilterAltitudeLength / sizeof(wchar_t));
			strncpy_s(ne.Altitude, sizeof(ne.Altitude), WideToUtf8(altitude).c_str(), _TRUNCATE);
			ne.Instances = mf.NumberOfInstances;
			ne.FrameId = mf.FrameID;
			ne.IsLegacy = 0;
		}
		else if (info->Flags & FLTFL_ASI_IS_LEGACYFILTER) {
			auto& lf = info->Type.LegacyFilter;
			auto* name = (wchar_t*)((BYTE*)info + lf.FilterNameBufferOffset);
			std::wstring filterName(name, lf.FilterNameLength / sizeof(wchar_t));
			strncpy_s(ne.Name, sizeof(ne.Name), WideToUtf8(filterName).c_str(), _TRUNCATE);
			auto* alt = (wchar_t*)((BYTE*)info + lf.FilterAltitudeBufferOffset);
			std::wstring altitude(alt, lf.FilterAltitudeLength / sizeof(wchar_t));
			strncpy_s(ne.Altitude, sizeof(ne.Altitude), WideToUtf8(altitude).c_str(), _TRUNCATE);
			ne.IsLegacy = 1;
		}
		netEntries.push_back(ne);
		hr = ::FilterFindNext(hFind, FilterAggregateStandardInformation, buf, sizeof(buf), &bytesReturned);
	}
	if (hFind != INVALID_HANDLE_VALUE) ::FilterFindClose(hFind);
	SendResponse(sock, MSG_RESP_MINIFILTERS, WINSYS_STATUS_OK, netEntries.data(), static_cast<uint32_t>(netEntries.size() * sizeof(MiniFilterNet)));
}

void ServerHandler::HandleFilterInstances(SOCKET sock, const void* payload, uint32_t size) {
	if (size < sizeof(FilterInstanceRequestNet)) {
		SendResponse(sock, MSG_RESP_FILTER_INSTANCES, WINSYS_STATUS_ERROR, nullptr, 0);
		return;
	}
	auto* req = (const FilterInstanceRequestNet*)payload;
	auto filterNameW = Utf8ToWide(req->FilterName);

	std::vector<FilterInstanceNet> netEntries;
	BYTE buf[4096]{};
	HANDLE hFind = INVALID_HANDLE_VALUE;
	DWORD bytesReturned = 0;
	HRESULT hr = ::FilterInstanceFindFirst(filterNameW.c_str(), InstanceFullInformation, buf, sizeof(buf), &bytesReturned, &hFind);
	while (SUCCEEDED(hr)) {
		auto* info = (PINSTANCE_FULL_INFORMATION)buf;
		FilterInstanceNet ne{};
		auto* instName = (wchar_t*)((BYTE*)info + info->InstanceNameBufferOffset);
		std::wstring instanceName(instName, info->InstanceNameLength / sizeof(wchar_t));
		strncpy_s(ne.InstanceName, sizeof(ne.InstanceName), WideToUtf8(instanceName).c_str(), _TRUNCATE);
		auto* volName = (wchar_t*)((BYTE*)info + info->VolumeNameBufferOffset);
		std::wstring volumeName(volName, info->VolumeNameLength / sizeof(wchar_t));
		strncpy_s(ne.VolumeName, sizeof(ne.VolumeName), WideToUtf8(volumeName).c_str(), _TRUNCATE);
		netEntries.push_back(ne);
		hr = ::FilterInstanceFindNext(hFind, InstanceFullInformation, buf, sizeof(buf), &bytesReturned);
	}
	if (hFind != INVALID_HANDLE_VALUE) ::FilterInstanceFindClose(hFind);
	SendResponse(sock, MSG_RESP_FILTER_INSTANCES, WINSYS_STATUS_OK, netEntries.data(), static_cast<uint32_t>(netEntries.size() * sizeof(FilterInstanceNet)));
}

void ServerHandler::HandleObjDirectory(SOCKET sock, const void* payload, uint32_t size) {
	std::wstring path = L"\\";
	if (size >= sizeof(ObjDirectoryRequestNet)) {
		auto* req = (const ObjDirectoryRequestNet*)payload;
		path = Utf8ToWide(req->Path);
	}

	UNICODE_STRING uniPath;
	::RtlInitUnicodeString(&uniPath, path.c_str());
	OBJECT_ATTRIBUTES objAttr;
	InitializeObjectAttributes(&objAttr, &uniPath, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

	HANDLE hDir = nullptr;
	NTSTATUS status = ::NtOpenDirectoryObject(&hDir, DIRECTORY_QUERY, &objAttr);
	if (status != 0 || !hDir) {
		SendResponse(sock, MSG_RESP_OBJ_DIRECTORY, WINSYS_STATUS_ERROR, nullptr, 0);
		return;
	}

	struct OBJECT_DIRECTORY_INFORMATION {
		UNICODE_STRING Name;
		UNICODE_STRING TypeName;
	};

	std::vector<ObjectEntryNet> netEntries;
	BYTE buffer[16384]{};
	ULONG context = 0;
	BOOLEAN restart = TRUE;
	ULONG returnLength = 0;

	while (::NtQueryDirectoryObject(hDir, buffer, sizeof(buffer), FALSE, restart, &context, &returnLength) == 0) {
		restart = FALSE;
		auto* entry = (OBJECT_DIRECTORY_INFORMATION*)buffer;
		while (entry->Name.Buffer) {
			ObjectEntryNet ne{};
			std::wstring name(entry->Name.Buffer, entry->Name.Length / sizeof(wchar_t));
			std::wstring typeName(entry->TypeName.Buffer, entry->TypeName.Length / sizeof(wchar_t));
			strncpy_s(ne.Name, sizeof(ne.Name), WideToUtf8(name).c_str(), _TRUNCATE);
			strncpy_s(ne.TypeName, sizeof(ne.TypeName), WideToUtf8(typeName).c_str(), _TRUNCATE);
			ne.IsDirectory = (typeName == L"Directory") ? 1 : 0;

			std::wstring fullPath = (path == L"\\") ? (L"\\" + name) : (path + L"\\" + name);
			strncpy_s(ne.FullPath, sizeof(ne.FullPath), WideToUtf8(fullPath).c_str(), _TRUNCATE);

			// Resolve symbolic links
			if (typeName == L"SymbolicLink") {
				UNICODE_STRING linkPath;
				::RtlInitUnicodeString(&linkPath, fullPath.c_str());
				OBJECT_ATTRIBUTES linkAttr;
				InitializeObjectAttributes(&linkAttr, &linkPath, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
				HANDLE hLink = nullptr;
				if (::NtOpenSymbolicLinkObject(&hLink, SYMBOLIC_LINK_QUERY, &linkAttr) == 0) {
					wchar_t targetBuf[512]{};
					UNICODE_STRING target;
					target.Buffer = targetBuf;
					target.Length = 0;
					target.MaximumLength = sizeof(targetBuf);
					if (::NtQuerySymbolicLinkObject(hLink, &target, nullptr) == 0) {
						std::wstring targetStr(target.Buffer, target.Length / sizeof(wchar_t));
						strncpy_s(ne.SymLinkTarget, sizeof(ne.SymLinkTarget), WideToUtf8(targetStr).c_str(), _TRUNCATE);
					}
					::NtClose(hLink);
				}
			}
			netEntries.push_back(ne);
			entry++;
		}
	}
	::NtClose(hDir);
	SendResponse(sock, MSG_RESP_OBJ_DIRECTORY, WINSYS_STATUS_OK, netEntries.data(), static_cast<uint32_t>(netEntries.size() * sizeof(ObjectEntryNet)));
}

void ServerHandler::HandleNtdllFunctions(SOCKET sock) {
	std::vector<NtdllFunctionNet> netEntries;
	HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
	if (!ntdll) {
		SendResponse(sock, MSG_RESP_NTDLL_FUNCTIONS, WINSYS_STATUS_ERROR, nullptr, 0);
		return;
	}

	auto* dos = (IMAGE_DOS_HEADER*)ntdll;
	auto* nt = (IMAGE_NT_HEADERS*)((BYTE*)ntdll + dos->e_lfanew);
	auto& exportDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (!exportDir.VirtualAddress) {
		SendResponse(sock, MSG_RESP_NTDLL_FUNCTIONS, WINSYS_STATUS_ERROR, nullptr, 0);
		return;
	}

	auto* exp = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)ntdll + exportDir.VirtualAddress);
	auto* names = (DWORD*)((BYTE*)ntdll + exp->AddressOfNames);
	auto* ordinals = (WORD*)((BYTE*)ntdll + exp->AddressOfNameOrdinals);
	auto* functions = (DWORD*)((BYTE*)ntdll + exp->AddressOfFunctions);

	for (DWORD i = 0; i < exp->NumberOfNames; i++) {
		auto* name = (const char*)((BYTE*)ntdll + names[i]);
		if (name[0] != 'Z' || name[1] != 'w') continue;
		auto* funcAddr = (BYTE*)ntdll + functions[ordinals[i]];
		// Look for mov eax, <serviceId> pattern: B8 xx xx xx xx
		if (funcAddr[0] == 0x4C && funcAddr[1] == 0x8B && funcAddr[2] == 0xD1 && funcAddr[3] == 0xB8) {
			// x64: mov r10, rcx; mov eax, <id>
			DWORD serviceId = *(DWORD*)(funcAddr + 4);
			NtdllFunctionNet ne{};
			ne.ServiceId = serviceId;
			strncpy_s(ne.Name, sizeof(ne.Name), name, _TRUNCATE);
			netEntries.push_back(ne);
		}
		else if (funcAddr[0] == 0xB8) {
			// x86: mov eax, <id>
			DWORD serviceId = *(DWORD*)(funcAddr + 1);
			NtdllFunctionNet ne{};
			ne.ServiceId = serviceId;
			strncpy_s(ne.Name, sizeof(ne.Name), name, _TRUNCATE);
			netEntries.push_back(ne);
		}
	}
	SendResponse(sock, MSG_RESP_NTDLL_FUNCTIONS, WINSYS_STATUS_OK, netEntries.data(), static_cast<uint32_t>(netEntries.size() * sizeof(NtdllFunctionNet)));
}

void ServerHandler::HandleInstrumentationCallbacks(SOCKET sock) {
	if (!DriverHelper::IsDriverLoaded()) {
		// User-mode fallback: enumerate processes and query instrumentation callbacks
		std::vector<InstrumentationCbNet> netEntries;

		using NtQueryInformationProcessFn = LONG(WINAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
		auto NtQueryInformationProcess = (NtQueryInformationProcessFn)::GetProcAddress(
			::GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
		if (!NtQueryInformationProcess) {
			SendResponse(sock, MSG_RESP_INSTRUMENTATION_CB, WINSYS_STATUS_ERROR, nullptr, 0);
			return;
		}

		DWORD pids[4096];
		DWORD bytesReturned = 0;
		if (!::K32EnumProcesses(pids, sizeof(pids), &bytesReturned)) {
			SendResponse(sock, MSG_RESP_INSTRUMENTATION_CB, WINSYS_STATUS_ERROR, nullptr, 0);
			return;
		}
		DWORD count = bytesReturned / sizeof(DWORD);
		for (DWORD i = 0; i < count; i++) {
			if (pids[i] == 0) continue;
			HANDLE hProc = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pids[i]);
			if (!hProc) continue;

			struct { ULONG_PTR Callback; } cbInfo{};
			ULONG retLen = 0;
			// ProcessInstrumentationCallback = 40
			if (NtQueryInformationProcess(hProc, 40, &cbInfo, sizeof(cbInfo), &retLen) == 0 && cbInfo.Callback != 0) {
				InstrumentationCbNet ne{};
				ne.ProcessId = pids[i];
				ne.InstrumentationCallback = cbInfo.Callback;
				// Get image name
				char imgName[MAX_PATH]{};
				DWORD nameSize = MAX_PATH;
				::QueryFullProcessImageNameA(hProc, 0, imgName, &nameSize);
				const char* baseName = strrchr(imgName, '\\');
				strncpy_s(ne.ImageName, sizeof(ne.ImageName), baseName ? baseName + 1 : imgName, _TRUNCATE);
				netEntries.push_back(ne);
			}
			::CloseHandle(hProc);
		}
		SendResponse(sock, MSG_RESP_INSTRUMENTATION_CB, WINSYS_STATUS_OK, netEntries.data(),
			static_cast<uint32_t>(netEntries.size() * sizeof(InstrumentationCbNet)));
		return;
	}

	std::vector<INSTRUMENTATION_CB_ENTRY> entries;
	if (!DriverHelper::QueryInstrumentationCallbacks(entries)) {
		SendResponse(sock, MSG_RESP_INSTRUMENTATION_CB, WINSYS_STATUS_ERROR, nullptr, 0);
		return;
	}
	// Convert to net format
	std::vector<InstrumentationCbNet> netEntries;
	for (auto& e : entries) {
		InstrumentationCbNet ne{};
		ne.ProcessId = e.ProcessId;
		ne.InstrumentationCallback = e.InstrumentationCallback;
		strncpy_s(ne.ImageName, sizeof(ne.ImageName), e.ImageName, _TRUNCATE);
		netEntries.push_back(ne);
	}
	SendResponse(sock, MSG_RESP_INSTRUMENTATION_CB, WINSYS_STATUS_OK, netEntries.data(),
		static_cast<uint32_t>(netEntries.size() * sizeof(InstrumentationCbNet)));
}

void ServerHandler::HandleDseStatus(SOCKET sock) {
	DseStatusNet net{};
	net.SecureBootRegValue = 0xFFFFFFFF;
	net.VbsRegValue = 0xFFFFFFFF;

	if (DriverHelper::IsDriverLoaded()) {
		DSE_STATUS_INFO info{};
		if (DriverHelper::QueryDseStatus(info)) {
			net.CiAddress = info.CiAddress;
			net.gCiOptionsAddress = info.gCiOptionsAddress;
			net.gCiOptionsValue = info.gCiOptionsValue;
		}
	}

	// User-mode fallback for gCiOptionsValue
	if (net.gCiOptionsValue == 0) {
		using NtQuerySystemInformationFn = LONG(WINAPI*)(ULONG, PVOID, ULONG, PULONG);
		auto NtQuerySystemInformation = (NtQuerySystemInformationFn)::GetProcAddress(
			::GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
		if (NtQuerySystemInformation) {
			struct { ULONG Length; ULONG CodeIntegrityOptions; } ciInfo{};
			ciInfo.Length = sizeof(ciInfo);
			if (NtQuerySystemInformation(103, &ciInfo, sizeof(ciInfo), nullptr) == 0)
				net.gCiOptionsValue = ciInfo.CodeIntegrityOptions;
		}
	}

	// Read raw registry values for SecureBoot and VBS
	HKEY hKey = nullptr;
	if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
		DWORD val = 0, sz = sizeof(val);
		if (::RegQueryValueExW(hKey, L"UEFISecureBootEnabled", nullptr, nullptr, (LPBYTE)&val, &sz) == ERROR_SUCCESS)
			net.SecureBootRegValue = val;
		::RegCloseKey(hKey);
	}

	if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
		DWORD val = 0, sz = sizeof(val);
		if (::RegQueryValueExW(hKey, L"EnableVirtualizationBasedSecurity", nullptr, nullptr, (LPBYTE)&val, &sz) == ERROR_SUCCESS)
			net.VbsRegValue = val;
		::RegCloseKey(hKey);
	}

	SendResponse(sock, MSG_RESP_DSE_STATUS, WINSYS_STATUS_OK, &net, sizeof(net));
}

void ServerHandler::HandleKernelIntegrity(SOCKET sock) {
	if (!DriverHelper::IsDriverLoaded()) {
		SendResponse(sock, MSG_RESP_KERNEL_INTEGRITY, WINSYS_STATUS_NO_DRIVER, nullptr, 0);
		return;
	}
	std::vector<KERNEL_INTEGRITY_ENTRY> entries;
	if (!DriverHelper::QueryKernelIntegrity(entries)) {
		SendResponse(sock, MSG_RESP_KERNEL_INTEGRITY, WINSYS_STATUS_ERROR, nullptr, 0);
		return;
	}
	std::vector<KernelIntegrityNet> netEntries;
	for (auto& e : entries) {
		KernelIntegrityNet ne{};
		ne.FunctionAddress = e.FunctionAddress;
		ne.ExpectedFirstBytes = e.ExpectedFirstBytes;
		ne.ActualFirstBytes = e.ActualFirstBytes;
		strncpy_s(ne.FunctionName, sizeof(ne.FunctionName), e.FunctionName, _TRUNCATE);
		netEntries.push_back(ne);
	}
	SendResponse(sock, MSG_RESP_KERNEL_INTEGRITY, WINSYS_STATUS_OK, netEntries.data(),
		static_cast<uint32_t>(netEntries.size() * sizeof(KernelIntegrityNet)));
}

void ServerHandler::HandleByovdScan(SOCKET sock) {
	// Send all loaded drivers - client does vulnerability matching via LOLDrivers DB
	std::vector<ByovdEntryNet> netEntries;

	LPVOID drivers[1024]{};
	DWORD needed = 0;
	if (::EnumDeviceDrivers(drivers, sizeof(drivers), &needed)) {
		DWORD driverCount = needed / sizeof(LPVOID);
		for (DWORD i = 0; i < driverCount && i < 1024; i++) {
			WCHAR driverName[MAX_PATH]{};
			if (::GetDeviceDriverFileNameW(drivers[i], driverName, MAX_PATH) == 0)
				continue;

			const WCHAR* baseName = wcsrchr(driverName, L'\\');
			if (baseName) baseName++; else baseName = driverName;

			ByovdEntryNet ne{};
			char baseNameA[MAX_PATH]{};
			::WideCharToMultiByte(CP_UTF8, 0, baseName, -1, baseNameA, MAX_PATH, nullptr, nullptr);
			strncpy_s(ne.DriverName, sizeof(ne.DriverName), baseNameA, _TRUNCATE);

			char pathA[520]{};
			::WideCharToMultiByte(CP_UTF8, 0, driverName, -1, pathA, sizeof(pathA), nullptr, nullptr);
			strncpy_s(ne.DriverPath, sizeof(ne.DriverPath), pathA, _TRUNCATE);

			netEntries.push_back(ne);
		}
	}
	SendResponse(sock, MSG_RESP_BYOVD_SCAN, WINSYS_STATUS_OK, netEntries.data(),
		static_cast<uint32_t>(netEntries.size() * sizeof(ByovdEntryNet)));
}

void ServerHandler::HandleMemoryRead(SOCKET sock, const void* payload, uint32_t size) {
	if (!DriverHelper::IsDriverLoaded()) {
		SendResponse(sock, MSG_RESP_MEMORY_READ, WINSYS_STATUS_NO_DRIVER, nullptr, 0);
		return;
	}
	if (size < sizeof(MemoryReadRequestNet)) {
		SendResponse(sock, MSG_RESP_MEMORY_READ, WINSYS_STATUS_ERROR, nullptr, 0);
		return;
	}
	auto* req = (const MemoryReadRequestNet*)payload;
	MEMORY_READ_REQUEST driverReq{};
	driverReq.Pid = req->Pid;
	driverReq.Address = req->Address;
	driverReq.Size = req->Size;
	if (driverReq.Size > 4096) {
		SendResponse(sock, MSG_RESP_MEMORY_READ, WINSYS_STATUS_ERROR, nullptr, 0);
		return;
	}
	MEMORY_READ_RESULT driverResult{};
	if (DriverHelper::MemoryRead(driverReq, driverResult)) {
		MemoryReadResponseNet resp{};
		resp.BytesRead = driverResult.BytesRead;
		memcpy(resp.Data, driverResult.Data, driverResult.BytesRead);
		SendResponse(sock, MSG_RESP_MEMORY_READ, WINSYS_STATUS_OK, &resp, sizeof(resp));
	}
	else {
		SendResponse(sock, MSG_RESP_MEMORY_READ, WINSYS_STATUS_ERROR, nullptr, 0);
	}
}

void ServerHandler::HandleMemoryWrite(SOCKET sock, const void* payload, uint32_t size) {
	if (!DriverHelper::IsDriverLoaded()) {
		SendResponse(sock, MSG_RESP_MEMORY_WRITE, WINSYS_STATUS_NO_DRIVER, nullptr, 0);
		return;
	}
	if (size < sizeof(MemoryWriteRequestNet)) {
		SendResponse(sock, MSG_RESP_MEMORY_WRITE, WINSYS_STATUS_ERROR, nullptr, 0);
		return;
	}
	auto* req = (const MemoryWriteRequestNet*)payload;
	MEMORY_WRITE_REQUEST driverReq{};
	driverReq.Pid = req->Pid;
	driverReq.Address = req->Address;
	driverReq.Size = req->Size;
	if (driverReq.Size > sizeof(driverReq.Data) ||
		driverReq.Size > sizeof(req->Data)) {
		SendResponse(sock, MSG_RESP_MEMORY_WRITE, WINSYS_STATUS_ERROR, nullptr, 0);
		return;
	}
	memcpy(driverReq.Data, req->Data, driverReq.Size);
	MEMORY_WRITE_RESULT driverResult{};
	if (DriverHelper::MemoryWrite(driverReq, driverResult)) {
		MemoryWriteResponseNet resp{};
		resp.BytesWritten = driverResult.BytesWritten;
		SendResponse(sock, MSG_RESP_MEMORY_WRITE, WINSYS_STATUS_OK, &resp, sizeof(resp));
	}
	else {
		SendResponse(sock, MSG_RESP_MEMORY_WRITE, WINSYS_STATUS_ERROR, nullptr, 0);
	}
}

void ServerHandler::HandleCiPolicy(SOCKET sock) {
	typedef LONG(NTAPI* NtQuerySystemInformation_t)(ULONG, PVOID, ULONG, PULONG);
	static auto NtQSI = (NtQuerySystemInformation_t)::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
	if (!NtQSI) {
		SendResponse(sock, MSG_RESP_CI_POLICY, WINSYS_STATUS_ERROR, nullptr, 0);
		return;
	}
	struct { ULONG Length; ULONG CodeIntegrityOptions; } ciInfo{};
	ciInfo.Length = sizeof(ciInfo);
	ULONG retLen = 0;
	if (NtQSI(103, &ciInfo, sizeof(ciInfo), &retLen) == 0) {
		CiPolicyNet net{};
		net.CiOptions = ciInfo.CodeIntegrityOptions;
		SendResponse(sock, MSG_RESP_CI_POLICY, WINSYS_STATUS_OK, &net, sizeof(net));
	}
	else {
		SendResponse(sock, MSG_RESP_CI_POLICY, WINSYS_STATUS_ERROR, nullptr, 0);
	}
}

void ServerHandler::HandleHypervisorHooks(SOCKET sock) {
	std::vector<HypervisorHookEntryNet> entries;
	int cpuInfo[4]{};

	// Baseline rdtsc
	unsigned long long baselineTotal = 0;
	for (int i = 0; i < 1000; i++) {
		unsigned long long s = __rdtsc();
		unsigned long long e = __rdtsc();
		baselineTotal += (e - s);
	}
	unsigned long long baselineCycles = baselineTotal / 1000;

	struct { int leaf; const char* name; unsigned long long threshold; } leaves[] = {
		{ 0,          "CPUID (leaf 0)",          1000 },
		{ 1,          "CPUID (leaf 1)",          1000 },
		{ 0x40000000, "CPUID (leaf 0x40000000)", 1500 },
		{ 0x80000001, "CPUID (leaf 0x80000001)", 1000 },
	};

	for (auto& l : leaves) {
		unsigned long long total = 0;
		for (int i = 0; i < 1000; i++) {
			unsigned long long s = __rdtsc();
			__cpuid(cpuInfo, l.leaf);
			unsigned long long e = __rdtsc();
			total += (e - s);
		}
		HypervisorHookEntryNet entry{};
		strncpy_s(entry.FunctionName, sizeof(entry.FunctionName), l.name, _TRUNCATE);
		entry.AvgCycles = total / 1000;
		entry.BaselineCycles = baselineCycles;
		entry.TimingAnomaly = (entry.AvgCycles > l.threshold) ? 1 : 0;
		entries.push_back(entry);
	}

	SendResponse(sock, MSG_RESP_HYPERVISOR_HOOKS, WINSYS_STATUS_OK, entries.data(),
		static_cast<uint32_t>(entries.size() * sizeof(HypervisorHookEntryNet)));
}
