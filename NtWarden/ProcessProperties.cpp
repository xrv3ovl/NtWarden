#include "pch.h"
#include "ProcessProperties.h"
#include "Processes.h"
#include "LoggerView.h"
#include "NativeSystem.h"
#include <TlHelp32.h>
#include <filesystem>
#include <algorithm>
#include <future>

#pragma comment(lib, "Ntdll.lib")

typedef NTSTATUS(NTAPI* NtQueryObject_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtDuplicateObject_t)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);

constexpr ULONG ObjNameInfoClass = 1;
constexpr ULONG ObjTypeInfoClass = 2;

struct OBJ_TYPE_INFO {
	UNICODE_STRING TypeName;
};

namespace {
	std::string WideToUtf8(const std::wstring& ws) {
		if (ws.empty())
			return {};

		int size = ::WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), nullptr, 0, nullptr, nullptr);
		std::string result(size, '\0');
		::WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), result.data(), size, nullptr, nullptr);
		return result;
	}

	bool IsWindowsPath(const std::wstring& path) {
		wchar_t windowsDir[MAX_PATH]{};
		if (::GetWindowsDirectoryW(windowsDir, _countof(windowsDir)) == 0)
			return false;

		std::wstring windowsRoot = windowsDir;
		if (!windowsRoot.empty() && windowsRoot.back() != L'\\')
			windowsRoot += L'\\';

		return path.size() >= windowsRoot.size() && _wcsnicmp(path.c_str(), windowsRoot.c_str(), windowsRoot.size()) == 0;
	}

	bool LooksLikeSystemDllName(const std::wstring& name) {
		static constexpr const wchar_t* kCommonNames[] = {
			L"version.dll", L"winmm.dll", L"dwmapi.dll", L"cryptsp.dll", L"dbghelp.dll",
			L"apphelp.dll", L"comctl32.dll", L"wtsapi32.dll", L"uxtheme.dll", L"propsys.dll"
		};

		for (auto candidate : kCommonNames) {
			if (_wcsicmp(name.c_str(), candidate) == 0)
				return true;
		}
		return false;
	}
}

ProcessProperties::ProcessProperties(std::string name, std::shared_ptr<WinSys::ProcessInfo> pi) 
	: WindowProperties(std::move(name)), _pi(std::move(pi)) {
	_vmTracker = std::make_unique<WinSys::ProcessVMTracker>(_pi->Id);
}

WinSys::ProcessInfo* ProcessProperties::GetProcess() const {
	return _pi.get();
}

void ProcessProperties::SetProcess(std::shared_ptr<WinSys::ProcessInfo> pi) {
	_pi = std::move(pi);
	_vmTracker = std::make_unique<WinSys::ProcessVMTracker>(_pi->Id);
	_lastRegionRefreshTick = 0;
	_lastModuleRefreshTick = 0;
}

void ProcessProperties::RefreshMemoryRegions() {
	if (_vmTracker == nullptr || !_vmTracker->IsValid())
		return;

	auto now = ::GetTickCount64();
	if (_lastRegionRefreshTick != 0 && now - _lastRegionRefreshTick < 1500)
		return;

	_lastRegionRefreshTick = now;
	_vmTracker->EnumRegions();
}

void ProcessProperties::ForceRefreshMemoryRegions() {
	if (_vmTracker == nullptr || !_vmTracker->IsValid())
		return;

	_lastRegionRefreshTick = ::GetTickCount64();
	_vmTracker->EnumRegions();
}

const std::vector<std::shared_ptr<WinSys::MemoryRegionItem>>& ProcessProperties::GetMemoryRegions() const {
	return _vmTracker ? _vmTracker->GetRegions() : _emptyRegions;
}

void ProcessProperties::RefreshModules() {
	auto now = ::GetTickCount64();
	if (_lastModuleRefreshTick != 0 && now - _lastModuleRefreshTick < 1500)
		return;

	_lastModuleRefreshTick = now;
	_modules.clear();

	HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, _pi->Id);
	if (snapshot == INVALID_HANDLE_VALUE)
		return;

	std::wstring processDir;
	auto imagePath = _pi->GetNativeImagePath();
	if (!imagePath.empty()) {
		std::filesystem::path p(imagePath);
		processDir = p.parent_path().native();
	}

	MODULEENTRY32W me{};
	me.dwSize = sizeof(me);
	if (::Module32FirstW(snapshot, &me)) {
		do {
			DllEntry entry;
			entry.ModuleName = WideToUtf8(me.szModule);
			entry.ModulePath = WideToUtf8(me.szExePath);
			entry.BaseAddress = reinterpret_cast<unsigned long long>(me.modBaseAddr);
			entry.Size = me.modBaseSize;
			entry.ExistsOnDisk = ::GetFileAttributesW(me.szExePath) != INVALID_FILE_ATTRIBUTES;

			std::wstring modulePath = me.szExePath;
			std::wstring moduleDir = std::filesystem::path(modulePath).parent_path().native();
			const bool appLocal = !processDir.empty() && _wcsicmp(moduleDir.c_str(), processDir.c_str()) == 0;
			entry.SideLoadCandidate = entry.ExistsOnDisk && appLocal && !IsWindowsPath(modulePath) &&
				LooksLikeSystemDllName(std::filesystem::path(modulePath).filename().native());

			_modules.push_back(std::move(entry));
		} while (::Module32NextW(snapshot, &me));
	}

	::CloseHandle(snapshot);
}

void ProcessProperties::ForceRefreshModules() {
	_lastModuleRefreshTick = 0;
	RefreshModules();
}

const std::vector<ProcessProperties::DllEntry>& ProcessProperties::GetModules() const {
	return _modules;
}

// === Handle Enumeration ===

namespace {
	constexpr ULONG PROCESS_TERMINATE_FLAG          = 0x0001;
	constexpr ULONG PROCESS_CREATE_THREAD_FLAG      = 0x0002;
	constexpr ULONG PROCESS_VM_OPERATION_FLAG       = 0x0008;
	constexpr ULONG PROCESS_VM_READ_FLAG            = 0x0010;
	constexpr ULONG PROCESS_VM_WRITE_FLAG           = 0x0020;
	constexpr ULONG PROCESS_DUP_HANDLE_FLAG         = 0x0040;
	constexpr ULONG PROCESS_CREATE_PROCESS_FLAG     = 0x0080;
	constexpr ULONG PROCESS_SET_INFORMATION_FLAG    = 0x0200;
	constexpr ULONG PROCESS_QUERY_INFORMATION_FLAG  = 0x0400;
	constexpr ULONG PROCESS_SUSPEND_RESUME_FLAG     = 0x0800;
	constexpr ULONG PROCESS_ALL_ACCESS_FLAG         = 0x001FFFFF;

	constexpr ULONG THREAD_TERMINATE_FLAG           = 0x0001;
	constexpr ULONG THREAD_SUSPEND_RESUME_FLAG      = 0x0002;
	constexpr ULONG THREAD_GET_CONTEXT_FLAG         = 0x0008;
	constexpr ULONG THREAD_SET_CONTEXT_FLAG         = 0x0010;
	constexpr ULONG THREAD_SET_THREAD_TOKEN_FLAG    = 0x0080;
	constexpr ULONG THREAD_IMPERSONATE_FLAG         = 0x0100;
	constexpr ULONG THREAD_ALL_ACCESS_FLAG          = 0x001FFFFF;

	constexpr ULONG TOKEN_ASSIGN_PRIMARY_FLAG       = 0x0001;
	constexpr ULONG TOKEN_DUPLICATE_FLAG            = 0x0002;
	constexpr ULONG TOKEN_IMPERSONATE_FLAG          = 0x0004;
	constexpr ULONG TOKEN_QUERY_FLAG                = 0x0008;
	constexpr ULONG TOKEN_ADJUST_PRIVILEGES_FLAG    = 0x0020;
	constexpr ULONG TOKEN_ADJUST_DEFAULT_FLAG       = 0x0080;
	constexpr ULONG TOKEN_ALL_ACCESS_FLAG           = 0x000F01FF;

	constexpr ULONG SECTION_MAP_WRITE_FLAG          = 0x0002;
	constexpr ULONG SECTION_MAP_EXECUTE_FLAG        = 0x0008;
	constexpr ULONG SECTION_ALL_ACCESS_FLAG         = 0x000F001F;

	constexpr ULONG FILE_WRITE_DATA_FLAG            = 0x0002;
	constexpr ULONG FILE_APPEND_DATA_FLAG           = 0x0004;
	constexpr ULONG FILE_EXECUTE_FLAG               = 0x0020;
	constexpr ULONG DELETE_FLAG                     = 0x00010000;
	constexpr ULONG WRITE_DAC_FLAG                  = 0x00040000;
	constexpr ULONG WRITE_OWNER_FLAG                = 0x00080000;

	constexpr ULONG KEY_SET_VALUE_FLAG              = 0x0002;
	constexpr ULONG KEY_CREATE_SUB_KEY_FLAG         = 0x0004;

	struct AccessFlag { ULONG mask; const char* name; };

	std::string DecodeProcessAccess(ULONG access) {
		if ((access & PROCESS_ALL_ACCESS_FLAG) == PROCESS_ALL_ACCESS_FLAG) return "ALL_ACCESS";
		std::string s;
		static const AccessFlag flags[] = {
			{PROCESS_CREATE_THREAD_FLAG, "CREATE_THREAD"}, {PROCESS_VM_OPERATION_FLAG, "VM_OP"},
			{PROCESS_VM_READ_FLAG, "VM_READ"}, {PROCESS_VM_WRITE_FLAG, "VM_WRITE"},
			{PROCESS_DUP_HANDLE_FLAG, "DUP_HANDLE"}, {PROCESS_TERMINATE_FLAG, "TERMINATE"},
			{PROCESS_CREATE_PROCESS_FLAG, "CREATE_PROCESS"}, {PROCESS_SET_INFORMATION_FLAG, "SET_INFO"},
			{PROCESS_QUERY_INFORMATION_FLAG, "QUERY_INFO"}, {PROCESS_SUSPEND_RESUME_FLAG, "SUSPEND_RESUME"},
		};
		for (auto& f : flags) { if (access & f.mask) { if (!s.empty()) s += " | "; s += f.name; } }
		return s.empty() ? "QUERY_LIMITED" : s;
	}

	std::string DecodeThreadAccess(ULONG access) {
		if ((access & THREAD_ALL_ACCESS_FLAG) == THREAD_ALL_ACCESS_FLAG) return "ALL_ACCESS";
		std::string s;
		static const AccessFlag flags[] = {
			{THREAD_SET_CONTEXT_FLAG, "SET_CONTEXT"}, {THREAD_GET_CONTEXT_FLAG, "GET_CONTEXT"},
			{THREAD_SUSPEND_RESUME_FLAG, "SUSPEND_RESUME"}, {THREAD_TERMINATE_FLAG, "TERMINATE"},
			{THREAD_SET_THREAD_TOKEN_FLAG, "SET_TOKEN"}, {THREAD_IMPERSONATE_FLAG, "IMPERSONATE"},
		};
		for (auto& f : flags) { if (access & f.mask) { if (!s.empty()) s += " | "; s += f.name; } }
		return s.empty() ? "QUERY_LIMITED" : s;
	}

	std::string DecodeTokenAccess(ULONG access) {
		if ((access & TOKEN_ALL_ACCESS_FLAG) == TOKEN_ALL_ACCESS_FLAG) return "ALL_ACCESS";
		std::string s;
		static const AccessFlag flags[] = {
			{TOKEN_ASSIGN_PRIMARY_FLAG, "ASSIGN_PRIMARY"}, {TOKEN_DUPLICATE_FLAG, "DUPLICATE"},
			{TOKEN_IMPERSONATE_FLAG, "IMPERSONATE"}, {TOKEN_QUERY_FLAG, "QUERY"},
			{TOKEN_ADJUST_PRIVILEGES_FLAG, "ADJUST_PRIVS"}, {TOKEN_ADJUST_DEFAULT_FLAG, "ADJUST_DEFAULT"},
		};
		for (auto& f : flags) { if (access & f.mask) { if (!s.empty()) s += " | "; s += f.name; } }
		return s.empty() ? "QUERY" : s;
	}

	std::string DecodeSectionAccess(ULONG access) {
		if ((access & SECTION_ALL_ACCESS_FLAG) == SECTION_ALL_ACCESS_FLAG) return "ALL_ACCESS";
		std::string s;
		static const AccessFlag flags[] = {
			{SECTION_MAP_WRITE_FLAG, "MAP_WRITE"}, {SECTION_MAP_EXECUTE_FLAG, "MAP_EXECUTE"},
			{0x0001, "QUERY"}, {0x0004, "MAP_READ"},
		};
		for (auto& f : flags) { if (access & f.mask) { if (!s.empty()) s += " | "; s += f.name; } }
		return s.empty() ? "QUERY" : s;
	}

	std::string DecodeFileAccess(ULONG access) {
		std::string s;
		static const AccessFlag flags[] = {
			{0x0001, "READ_DATA"}, {FILE_WRITE_DATA_FLAG, "WRITE_DATA"},
			{FILE_APPEND_DATA_FLAG, "APPEND"}, {0x0080, "READ_ATTR"},
			{FILE_EXECUTE_FLAG, "EXECUTE"}, {DELETE_FLAG, "DELETE"},
			{WRITE_DAC_FLAG, "WRITE_DAC"}, {WRITE_OWNER_FLAG, "WRITE_OWNER"},
		};
		for (auto& f : flags) { if (access & f.mask) { if (!s.empty()) s += " | "; s += f.name; } }
		return s.empty() ? "READ" : s;
	}

	std::string DecodeKeyAccess(ULONG access) {
		std::string s;
		static const AccessFlag flags[] = {
			{0x0001, "QUERY_VALUE"}, {KEY_SET_VALUE_FLAG, "SET_VALUE"},
			{KEY_CREATE_SUB_KEY_FLAG, "CREATE_SUB_KEY"}, {0x0008, "ENUM_SUB_KEYS"},
			{DELETE_FLAG, "DELETE"}, {WRITE_DAC_FLAG, "WRITE_DAC"},
		};
		for (auto& f : flags) { if (access & f.mask) { if (!s.empty()) s += " | "; s += f.name; } }
		return s.empty() ? "READ" : s;
	}

	std::string DecodeHandleAccess(const std::string& type, ULONG access) {
		if (type == "Process") return DecodeProcessAccess(access);
		if (type == "Thread") return DecodeThreadAccess(access);
		if (type == "Token") return DecodeTokenAccess(access);
		if (type == "Section") return DecodeSectionAccess(access);
		if (type == "File" || type == "Directory") return DecodeFileAccess(access);
		if (type == "Key") return DecodeKeyAccess(access);
		char buf[32];
		snprintf(buf, sizeof(buf), "0x%08X", access);
		return buf;
	}
}

void ProcessProperties::ClassifyHandleSecurity(HandleEntry& he) {
	const auto& type = he.TypeName;
	ULONG acc = he.GrantedAccess;

	if (type == "Process") {
		bool canInject = (acc & PROCESS_CREATE_THREAD_FLAG) && (acc & PROCESS_VM_WRITE_FLAG) && (acc & PROCESS_VM_OPERATION_FLAG);
		bool allAccess = (acc & PROCESS_ALL_ACCESS_FLAG) == PROCESS_ALL_ACCESS_FLAG;
		if (allAccess) { he.Suspicious = true; he.SecurityNote = "PROCESS_ALL_ACCESS - full control over target process"; }
		else if (canInject) { he.Suspicious = true; he.SecurityNote = "Injection-capable: CREATE_THREAD + VM_WRITE + VM_OP"; }
		else if (acc & PROCESS_VM_WRITE_FLAG) { he.Suspicious = true; he.SecurityNote = "Can write to process memory"; }
		else if (acc & PROCESS_DUP_HANDLE_FLAG) { he.Suspicious = true; he.SecurityNote = "Can duplicate handles from target (privilege escalation vector)"; }
	}
	else if (type == "Thread") {
		bool allAccess = (acc & THREAD_ALL_ACCESS_FLAG) == THREAD_ALL_ACCESS_FLAG;
		if (allAccess) { he.Suspicious = true; he.SecurityNote = "THREAD_ALL_ACCESS - can hijack thread execution"; }
		else if ((acc & THREAD_SET_CONTEXT_FLAG) && (acc & THREAD_SUSPEND_RESUME_FLAG)) { he.Suspicious = true; he.SecurityNote = "Thread hijack capable: SET_CONTEXT + SUSPEND_RESUME"; }
		else if (acc & THREAD_SET_CONTEXT_FLAG) { he.Suspicious = true; he.SecurityNote = "SET_CONTEXT - can modify thread registers (RIP hijack)"; }
		else if (acc & THREAD_IMPERSONATE_FLAG) { he.Suspicious = true; he.SecurityNote = "Can impersonate thread token"; }
	}
	else if (type == "Token") {
		bool allAccess = (acc & TOKEN_ALL_ACCESS_FLAG) == TOKEN_ALL_ACCESS_FLAG;
		if (allAccess) { he.Suspicious = true; he.SecurityNote = "TOKEN_ALL_ACCESS - full token manipulation"; }
		else if ((acc & TOKEN_DUPLICATE_FLAG) && (acc & TOKEN_IMPERSONATE_FLAG)) { he.Suspicious = true; he.SecurityNote = "Can duplicate + impersonate token (privilege escalation)"; }
		else if (acc & TOKEN_ADJUST_PRIVILEGES_FLAG) { he.Suspicious = true; he.SecurityNote = "Can adjust token privileges (enable SeDebugPrivilege, etc.)"; }
		else if (acc & TOKEN_ASSIGN_PRIMARY_FLAG) { he.Suspicious = true; he.SecurityNote = "Can assign as primary token to new process"; }
	}
	else if (type == "Section") {
		if ((acc & SECTION_MAP_WRITE_FLAG) && (acc & SECTION_MAP_EXECUTE_FLAG)) { he.Suspicious = true; he.SecurityNote = "Section with WRITE + EXECUTE mapping (shellcode injection vector)"; }
		else if ((acc & SECTION_ALL_ACCESS_FLAG) == SECTION_ALL_ACCESS_FLAG) { he.Suspicious = true; he.SecurityNote = "SECTION_ALL_ACCESS"; }
	}
	else if (type == "DebugObject") {
		he.Suspicious = true; he.SecurityNote = "Debug object - process is being debugged or is debugging another";
	}
	else if (type == "File" || type == "Directory") {
		const auto& name = he.ObjectName;
		if (acc & (WRITE_DAC_FLAG | WRITE_OWNER_FLAG)) { he.Suspicious = true; he.SecurityNote = "Can modify file security descriptor (WRITE_DAC/OWNER)"; }
		else if (name.find("\\SAM") != std::string::npos || name.find("\\SECURITY") != std::string::npos || name.find("\\config\\SYSTEM") != std::string::npos) { he.Suspicious = true; he.SecurityNote = "Handle to sensitive registry hive file"; }
		else if (name.find("\\lsass") != std::string::npos) { he.Suspicious = true; he.SecurityNote = "Handle to LSASS-related file"; }
	}
	else if (type == "Key") {
		const auto& name = he.ObjectName;
		if ((acc & KEY_SET_VALUE_FLAG) && (name.find("\\Run") != std::string::npos || name.find("\\Services") != std::string::npos || name.find("\\Image File Execution") != std::string::npos)) {
			he.Suspicious = true; he.SecurityNote = "Write access to persistence/hijack registry key";
		}
	}
}

std::vector<ProcessProperties::HandleEntry> ProcessProperties::EnumHandlesAsync(uint32_t pid) {
	std::vector<HandleEntry> results;

	static auto ntQueryObj = (NtQueryObject_t)::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), "NtQueryObject");
	static auto ntDupObj = (NtDuplicateObject_t)::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), "NtDuplicateObject");
	if (!ntQueryObj || !ntDupObj)
		return results;

	ULONG size = 1 << 20;
	std::vector<BYTE> buffer;
	for (int i = 0; i < 8; i++) {
		buffer.resize(size);
		ULONG returnLength = 0;
		auto status = ::NtQuerySystemInformation(SystemExtendedHandleInformationClass,
			buffer.data(), size, &returnLength);
		if (NT_SUCCESS(status)) { buffer.resize(returnLength ? returnLength : size); break; }
		if (status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL) { buffer.clear(); break; }
		size = returnLength ? returnLength + 4096 : size * 2;
	}
	if (buffer.empty())
		return results;

	auto info = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION_EX>(buffer.data());

	HANDLE hProcess = ::OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
	if (!hProcess)
		return results;

	std::unordered_map<USHORT, std::string> typeCache;

	for (ULONG_PTR i = 0; i < info->NumberOfHandles; i++) {
		const auto& entry = info->Handles[i];
		if (entry.UniqueProcessId != static_cast<ULONG_PTR>(pid))
			continue;

		HandleEntry he{};
		he.HandleValue = entry.HandleValue;
		he.Object = reinterpret_cast<unsigned long long>(entry.Object);
		he.GrantedAccess = entry.GrantedAccess;
		he.Attributes = entry.HandleAttributes;

		HANDLE hDup = nullptr;
		auto dupStatus = ntDupObj(hProcess, reinterpret_cast<HANDLE>(entry.HandleValue),
			::GetCurrentProcess(), &hDup, 0, 0, DUPLICATE_SAME_ACCESS);
		if (!NT_SUCCESS(dupStatus) || !hDup) {
			he.TypeName = "Type#" + std::to_string(entry.ObjectTypeIndex);
			he.DecodedAccess = DecodeHandleAccess(he.TypeName, he.GrantedAccess);
			results.push_back(std::move(he));
			continue;
		}

		auto typeIt = typeCache.find(entry.ObjectTypeIndex);
		if (typeIt != typeCache.end()) {
			he.TypeName = typeIt->second;
		}
		else {
			BYTE typeBuf[1024]{};
			ULONG retLen = 0;
			if (NT_SUCCESS(ntQueryObj(hDup, ObjTypeInfoClass, typeBuf, sizeof(typeBuf), &retLen))) {
				auto* typeInfo = reinterpret_cast<OBJ_TYPE_INFO*>(typeBuf);
				if (typeInfo->TypeName.Buffer && typeInfo->TypeName.Length > 0)
					he.TypeName = WideToUtf8(std::wstring(typeInfo->TypeName.Buffer, typeInfo->TypeName.Length / sizeof(WCHAR)));
			}
			if (he.TypeName.empty())
				he.TypeName = "Type#" + std::to_string(entry.ObjectTypeIndex);
			typeCache[entry.ObjectTypeIndex] = he.TypeName;
		}

		if (he.TypeName != "Thread" && he.TypeName != "Process" &&
			he.TypeName != "EtwRegistration" && he.TypeName != "ALPC Port") {
			ULONG nameLen = 0;
			ntQueryObj(hDup, ObjNameInfoClass, nullptr, 0, &nameLen);
			if (nameLen > 0 && nameLen < (1 << 16)) {
				std::vector<BYTE> nameBuf(nameLen);
				if (NT_SUCCESS(ntQueryObj(hDup, ObjNameInfoClass, nameBuf.data(), nameLen, &nameLen))) {
					auto* nameInfo = reinterpret_cast<UNICODE_STRING*>(nameBuf.data());
					if (nameInfo->Buffer && nameInfo->Length > 0)
						he.ObjectName = WideToUtf8(std::wstring(nameInfo->Buffer, nameInfo->Length / sizeof(WCHAR)));
				}
			}
		}

		::CloseHandle(hDup);

		he.DecodedAccess = DecodeHandleAccess(he.TypeName, he.GrantedAccess);
		ClassifyHandleSecurity(he);
		results.push_back(std::move(he));
	}

	::CloseHandle(hProcess);

	std::stable_sort(results.begin(), results.end(), [](const HandleEntry& a, const HandleEntry& b) {
		return a.Suspicious > b.Suspicious;
	});

	LoggerView::AddLog(LoggerView::UserModeLog, "Enumerated %zu handles for PID %u", results.size(), pid);
	return results;
}

void ProcessProperties::RefreshHandles() {
	if (_handleRefreshPending && _handleFuture.valid() &&
		_handleFuture.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
		_handles = _handleFuture.get();
		_handleRefreshPending = false;
		_lastHandleRefreshTick = ::GetTickCount64();
	}
}

void ProcessProperties::ForceRefreshHandles() {
	RefreshHandles();
	if (_handleRefreshPending)
		return;

	_handles.clear();
	_handleRefreshPending = true;
	_lastHandleRefreshTick = 0;
	auto pid = _pi->Id;
	_handleFuture = std::async(std::launch::async, EnumHandlesAsync, pid);
}

const std::vector<ProcessProperties::HandleEntry>& ProcessProperties::GetHandles() const {
	return _handles;
}

bool ProcessProperties::IsHandleRefreshPending() const {
	return _handleRefreshPending;
}
