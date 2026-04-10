#include "pch.h"
#include "imgui.h"
#include "ProcessSecurityView.h"
#include "LoggerView.h"
#include <TlHelp32.h>
#include <Psapi.h>
#include <winternl.h>
#include <intrin.h>
#include <capstone/capstone.h>
#include "NativeSystem.h"

#pragma comment(lib, "Ntdll.lib")

// NT object query types
typedef NTSTATUS(NTAPI* NtQueryObject_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtDuplicateObject_t)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);

constexpr ULONG ObjectNameInformationClass = 1;
constexpr ULONG ObjectTypeInformationClass = 2;

struct OBJECT_TYPE_INFORMATION_T {
	UNICODE_STRING TypeName;
	// remaining fields not needed
};

using namespace ImGui;

// Undocumented NT types
typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

namespace {
	NtQueryInformationProcess_t GetNtQueryInformationProcess() {
		static auto fn = (NtQueryInformationProcess_t)::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
		return fn;
	}

	std::string ProtectToString(DWORD prot) {
		std::string s;
		if (prot & PAGE_EXECUTE) s += "X ";
		if (prot & PAGE_EXECUTE_READ) s += "RX ";
		if (prot & PAGE_EXECUTE_READWRITE) s += "RWX ";
		if (prot & PAGE_EXECUTE_WRITECOPY) s += "RWX(C) ";
		if (prot & PAGE_READONLY) s += "R ";
		if (prot & PAGE_READWRITE) s += "RW ";
		if (prot & PAGE_WRITECOPY) s += "RW(C) ";
		if (prot & PAGE_NOACCESS) s += "NA ";
		if (prot & PAGE_GUARD) s += "G ";
		if (!s.empty() && s.back() == ' ') s.pop_back();
		return s.empty() ? "?" : s;
	}

	bool IsExecuteProtect(DWORD prot) {
		return (prot & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
	}

	std::string WideToUtf8(const std::wstring& ws) {
		if (ws.empty()) return {};
		int len = ::WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), nullptr, 0, nullptr, nullptr);
		std::string s(len, '\0');
		::WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), s.data(), len, nullptr, nullptr);
		return s;
	}

	std::string FormatBytes(const unsigned char* bytes, unsigned int count) {
		char buffer[24 * 3 + 1]{};
		char* cursor = buffer;
		for (unsigned int i = 0; i < count && i < 24; i++) {
			int written = sprintf_s(cursor, buffer + sizeof(buffer) - cursor, "%02X ", bytes[i]);
			if (written <= 0)
				break;
			cursor += written;
		}
		if (cursor != buffer && *(cursor - 1) == ' ')
			*(cursor - 1) = '\0';
		return buffer;
	}

	std::string DisassembleBytes(const unsigned char* bytes, unsigned int count, unsigned long long address) {
		if (!bytes || count == 0)
			return {};

		csh handle{};
#ifdef _WIN64
		const cs_mode mode = CS_MODE_64;
#else
		const cs_mode mode = CS_MODE_32;
#endif
		auto err = cs_open(CS_ARCH_X86, mode, &handle);
		if (err != CS_ERR_OK)
			return "Capstone initialization failed";

		cs_insn* insn = nullptr;
		size_t insnCount = cs_disasm(handle, bytes, count, address, 0, &insn);
		if (insnCount == 0) {
			cs_close(&handle);
			return "Unable to disassemble bytes";
		}

		std::string text;
		for (size_t i = 0; i < insnCount; i++) {
			char line[256]{};
			sprintf_s(line, "0x%016llX: %-8s %s",
				static_cast<unsigned long long>(insn[i].address),
				insn[i].mnemonic,
				insn[i].op_str);
			if (!text.empty())
				text += "\n";
			text += line;
		}

		cs_free(insn, insnCount);
		cs_close(&handle);
		return text;
	}
}

ProcessSecurityView::ProcessSecurityView() : ViewBase(0) {
}

void ProcessSecurityView::SetTargetPid(DWORD pid) {
	_targetPid = pid;
	_userHooksView.SetTargetPid(pid);
}

void ProcessSecurityView::RefreshNow() {
	if (_targetPid > 0) {
		ScanUnbackedMemory(_targetPid);
		ScanHollowing(_targetPid);
		ScanTokens(_targetPid);
		ScanJobObjects(_targetPid);
		ScanCfgStatus(_targetPid);
		ScanModuleStomping(_targetPid);
		ScanDirectSyscalls(_targetPid);
		ScanSyscallStubs(_targetPid);
		_userHooksView.RefreshNow();
	}
	ScanDebugObjects();
	ScanHypervisor();
	MarkUpdated();
}

bool ProcessSecurityView::HasPendingAsync() const {
	return _unbackedScanning || _hollowingScanning || _stompingScanning || _syscallScanning ||
		_stubScanning || _tokenScanning || _debugScanning || _jobScanning || _cfgScanning ||
		_userHooksView.HasPendingAsync();
}

void ProcessSecurityView::BuildWindow() {
	BuildToolBar();

	// Check async results
	if (_unbackedScanning && _unbackedFuture.valid() &&
		_unbackedFuture.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
		_unbackedMem = _unbackedFuture.get();
		_unbackedScanning = false;
	}
	if (_hollowingScanning && _hollowingFuture.valid() &&
		_hollowingFuture.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
		_hollowing = _hollowingFuture.get();
		_hollowingScanning = false;
	}
	if (_stompingScanning && _stompingFuture.valid() &&
		_stompingFuture.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
		_stompedSections = _stompingFuture.get();
		_stompingScanning = false;
	}
	if (_syscallScanning && _syscallFuture.valid() &&
		_syscallFuture.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
		_directSyscalls = _syscallFuture.get();
		_syscallScanning = false;
	}
	if (_stubScanning && _stubFuture.valid() &&
		_stubFuture.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
		_syscallStubs = _stubFuture.get();
		_stubScanning = false;
	}
	if (_tokenScanning && _tokenFuture.valid() &&
		_tokenFuture.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
		_tokenInfo = _tokenFuture.get();
		_tokenScanning = false;
	}
	if (_debugScanning && _debugFuture.valid() &&
		_debugFuture.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
		_debugObjects = _debugFuture.get();
		_debugScanning = false;
	}
	if (_jobScanning && _jobFuture.valid() &&
		_jobFuture.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
		_jobInfo = _jobFuture.get();
		_jobScanning = false;
	}
	if (_cfgScanning && _cfgFuture.valid() &&
		_cfgFuture.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
		_cfgInfo = _cfgFuture.get();
		_cfgScanning = false;
	}
	constexpr float sidebarWidth = 190.0f;
	if (BeginChild("##SecuritySidebar", ImVec2(sidebarWidth, 0), true)) {
		if (Selectable("Unbacked Memory", _activeSection == Section::UnbackedMemory))
			_activeSection = Section::UnbackedMemory;
		if (Selectable("Hollowing", _activeSection == Section::Hollowing))
			_activeSection = Section::Hollowing;
		if (Selectable("Module Stomping", _activeSection == Section::ModuleStomping))
			_activeSection = Section::ModuleStomping;
		if (Selectable("Direct Syscalls", _activeSection == Section::DirectSyscalls))
			_activeSection = Section::DirectSyscalls;
		if (Selectable("Syscall Stubs", _activeSection == Section::SyscallStubs))
			_activeSection = Section::SyscallStubs;
		if (Selectable("User Hooks", _activeSection == Section::UserHooks))
			_activeSection = Section::UserHooks;
		if (Selectable("Tokens", _activeSection == Section::Tokens))
			_activeSection = Section::Tokens;
		if (Selectable("Debug Objects", _activeSection == Section::DebugObjects))
			_activeSection = Section::DebugObjects;
		if (Selectable("Hypervisor", _activeSection == Section::Hypervisor))
			_activeSection = Section::Hypervisor;
		if (Selectable("Job Objects", _activeSection == Section::JobObjects))
			_activeSection = Section::JobObjects;
		if (Selectable("CFG Status", _activeSection == Section::CfgStatus))
			_activeSection = Section::CfgStatus;
	}
	EndChild();

	SameLine();

	if (BeginChild("##SecurityContent", ImVec2(0, 0), false)) {
		switch (_activeSection) {
		case Section::UnbackedMemory: BuildUnbackedMemTable(); break;
		case Section::Hollowing: BuildHollowingPanel(); break;
		case Section::ModuleStomping: BuildModuleStompingTable(); break;
		case Section::DirectSyscalls: BuildDirectSyscallTable(); break;
		case Section::SyscallStubs: BuildSyscallStubTable(); break;
		case Section::UserHooks: _userHooksView.BuildWindow(); break;
		case Section::Tokens: BuildTokenPanel(); break;
		case Section::DebugObjects: BuildDebugObjectTable(); break;
		case Section::Hypervisor: BuildHypervisorPanel(); break;
		case Section::JobObjects: BuildJobObjectPanel(); break;
		case Section::CfgStatus: BuildCfgPanel(); break;
		}
	}
	EndChild();
}

void ProcessSecurityView::BuildToolBar() {
	Text("PID: %u", _targetPid);
	SameLine();
	if (Button("Refresh")) {
		RefreshNow();
		LoggerView::AddLog(LoggerView::UserModeLog, "Refreshed process analysis for PID %u", _targetPid);
	}
	if (HasPendingAsync()) {
		SameLine();
		TextDisabled("Scanning...");
	}
	Separator();
}

/* =============== Unbacked Memory Scanner =============== */

void ProcessSecurityView::ScanUnbackedMemory(DWORD pid) {
	if (_unbackedScanning) return;
	_unbackedScanning = true;
	_unbackedFuture = std::async(std::launch::async, [pid]() -> std::vector<UnbackedMemEntry> {
		std::vector<UnbackedMemEntry> results;
		HANDLE hProc = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
		if (!hProc) return results;

		MEMORY_BASIC_INFORMATION mbi{};
		LPVOID addr = nullptr;
		while (::VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
			if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && IsExecuteProtect(mbi.Protect)) {
				UnbackedMemEntry entry;
				entry.BaseAddress = (unsigned long long)mbi.BaseAddress;
				entry.RegionSize = mbi.RegionSize;
				entry.Protect = mbi.Protect;
				entry.State = mbi.State;
				entry.Type = mbi.Type;
				entry.IsExecutable = true;
				entry.IsPrivate = true;
				entry.Details = "MEM_PRIVATE + EXECUTE - Not backed by file";
				results.push_back(std::move(entry));
			}
			addr = (LPBYTE)mbi.BaseAddress + mbi.RegionSize;
		}
		::CloseHandle(hProc);
		return results;
	});
}

void ProcessSecurityView::BuildUnbackedMemTable() {
	if (_unbackedScanning) {
		Text("Scanning for unbacked executable memory...");
		return;
	}
	if (!_unbackedMem.empty())
		TextColored(ImVec4(1.0f, 0.6f, 0.0f, 1.0f), "%zu suspicious unbacked executable region(s)", _unbackedMem.size());
	else if (_targetPid > 0)
		TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), "No unbacked executable memory found.");

	if (BeginTable("unbackedMemTable", 5, ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg)) {
		TableSetupScrollFreeze(1, 1);
		TableSetupColumn("Base Address", ImGuiTableColumnFlags_WidthFixed, 140.0f);
		TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 100.0f);
		TableSetupColumn("Protection");
		TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 80.0f);
		TableSetupColumn("Details");
		TableHeadersRow();

		for (const auto& entry : _unbackedMem) {
			TableNextRow();
			TableSetBgColor(ImGuiTableBgTarget_RowBg0, IM_COL32(180, 100, 0, 60));
			TableSetColumnIndex(0); Text("0x%llX", entry.BaseAddress);
			TableSetColumnIndex(1); Text("0x%llX", entry.RegionSize);
			TableSetColumnIndex(2); Text("%s", ProtectToString(entry.Protect).c_str());
			TableSetColumnIndex(3); Text("PRIVATE");
			TableSetColumnIndex(4); Text("%s", entry.Details.c_str());
		}
		EndTable();
	}
}

/* =============== Process Hollowing Detection =============== */

void ProcessSecurityView::ScanHollowing(DWORD pid) {
	if (_hollowingScanning) return;
	_hollowingScanning = true;
	_hollowingFuture = std::async(std::launch::async, [pid]() -> HollowingResult {
		HollowingResult result{};
		HANDLE hProc = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
		if (!hProc) return result;

		auto NtQIP = GetNtQueryInformationProcess();
		if (!NtQIP) { ::CloseHandle(hProc); return result; }

		PROCESS_BASIC_INFORMATION pbi{};
		ULONG retLen = 0;
		if (NtQIP(hProc, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen) != 0) {
			::CloseHandle(hProc);
			return result;
		}

#ifdef _WIN64
		unsigned long long pebImageBase = 0;
		SIZE_T bytesRead = 0;
		if (::ReadProcessMemory(hProc, (PBYTE)pbi.PebBaseAddress + 0x10, &pebImageBase, sizeof(pebImageBase), &bytesRead)) {
			result.PebImageBase = pebImageBase;
		}
#else
		unsigned long pebImageBase = 0;
		SIZE_T bytesRead = 0;
		if (::ReadProcessMemory(hProc, (PBYTE)pbi.PebBaseAddress + 0x08, &pebImageBase, sizeof(pebImageBase), &bytesRead)) {
			result.PebImageBase = pebImageBase;
		}
#endif

		IMAGE_DOS_HEADER dosHeader{};
		if (::ReadProcessMemory(hProc, (PVOID)result.PebImageBase, &dosHeader, sizeof(dosHeader), &bytesRead) && dosHeader.e_magic == IMAGE_DOS_SIGNATURE) {
			IMAGE_NT_HEADERS ntHeaders{};
			if (::ReadProcessMemory(hProc, (PBYTE)result.PebImageBase + dosHeader.e_lfanew, &ntHeaders, sizeof(ntHeaders), &bytesRead) && ntHeaders.Signature == IMAGE_NT_SIGNATURE) {
				result.ActualImageBase = ntHeaders.OptionalHeader.ImageBase;
			}
		}

		WCHAR imagePath[MAX_PATH]{};
		DWORD pathSize = MAX_PATH;
		if (::QueryFullProcessImageNameW(hProc, 0, imagePath, &pathSize))
			result.ImagePath = WideToUtf8(imagePath);

		result.Mismatched = (result.PebImageBase != 0 && result.ActualImageBase != 0 &&
			result.PebImageBase != result.ActualImageBase);
		result.Scanned = true;
		::CloseHandle(hProc);
		return result;
	});
}

void ProcessSecurityView::BuildHollowingPanel() {
	if (_hollowingScanning) {
		Text("Checking process hollowing indicators...");
		return;
	}
	if (!_hollowing.Scanned) {
		TextDisabled("Process hollowing data is not available yet for this process.");
		return;
	}

	if (_hollowing.Mismatched) {
		TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "POSSIBLE PROCESS HOLLOWING DETECTED!");
		Text("PEB ImageBaseAddress and PE header ImageBase do not match.");
	}
	else {
		TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), "No hollowing indicators found.");
	}

	Separator();
	Text("Image Path: %s", _hollowing.ImagePath.c_str());
	Text("PEB ImageBaseAddress: 0x%llX", _hollowing.PebImageBase);
	Text("PE Header ImageBase:  0x%llX", _hollowing.ActualImageBase);
	Text("Match: %s", _hollowing.Mismatched ? "MISMATCH" : "OK");
}

/* =============== Module Stomping Detection =============== */

void ProcessSecurityView::ScanModuleStomping(DWORD pid) {
	if (_stompingScanning) return;
	_stompingScanning = true;
	_stompingFuture = std::async(std::launch::async, [pid]() -> std::vector<StompedSection> {
		std::vector<StompedSection> results;
		HANDLE hSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
		if (hSnap == INVALID_HANDLE_VALUE) return results;

		HANDLE hProc = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
		if (!hProc) { ::CloseHandle(hSnap); return results; }

		MODULEENTRY32W me{};
		me.dwSize = sizeof(me);
		if (::Module32FirstW(hSnap, &me)) {
			do {
				// Load the disk copy
				HANDLE hFile = ::CreateFileW(me.szExePath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
				if (hFile == INVALID_HANDLE_VALUE) continue;

				DWORD fileSize = ::GetFileSize(hFile, nullptr);
				if (fileSize == 0 || fileSize > 256 * 1024 * 1024) { ::CloseHandle(hFile); continue; }

				std::vector<BYTE> diskImage(fileSize);
				DWORD bytesRead = 0;
				if (!::ReadFile(hFile, diskImage.data(), fileSize, &bytesRead, nullptr) || bytesRead != fileSize) {
					::CloseHandle(hFile);
					continue;
				}
				::CloseHandle(hFile);

				auto* dosHeader = (IMAGE_DOS_HEADER*)diskImage.data();
				if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) continue;
				auto* ntHeaders = (IMAGE_NT_HEADERS*)(diskImage.data() + dosHeader->e_lfanew);
				if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) continue;

				auto* sections = IMAGE_FIRST_SECTION(ntHeaders);
				for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
					// Only check executable sections (.text)
					if (!(sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;

					DWORD sectionRva = sections[i].VirtualAddress;
					DWORD rawSize = sections[i].SizeOfRawData;
					DWORD rawOffset = sections[i].PointerToRawData;

					if (rawOffset + rawSize > fileSize) continue;
					DWORD compareSize = min(rawSize, sections[i].Misc.VirtualSize);
					if (compareSize == 0) continue;

					std::vector<BYTE> memSection(compareSize);
					SIZE_T read = 0;
					if (!::ReadProcessMemory(hProc, me.modBaseAddr + sectionRva, memSection.data(), compareSize, &read) || read != compareSize)
						continue;

					// Compare bytes
					DWORD patchedCount = 0;
					for (DWORD j = 0; j < compareSize; j++) {
						if (memSection[j] != diskImage[rawOffset + j])
							patchedCount++;
					}

					if (patchedCount > 0) {
						StompedSection entry;
						entry.ModuleName = std::string((char*)me.szModule, (char*)me.szModule + wcslen(me.szModule));
						// Convert wide to narrow
						int len = ::WideCharToMultiByte(CP_UTF8, 0, me.szModule, -1, nullptr, 0, nullptr, nullptr);
						entry.ModuleName.resize(len > 0 ? len - 1 : 0);
						if (len > 0) ::WideCharToMultiByte(CP_UTF8, 0, me.szModule, -1, entry.ModuleName.data(), len, nullptr, nullptr);

						entry.SectionName = std::string((char*)sections[i].Name, strnlen((char*)sections[i].Name, 8));
						entry.MemoryAddress = (unsigned long long)(me.modBaseAddr + sectionRva);
						entry.SectionSize = compareSize;
						entry.PatchedBytes = patchedCount;
						entry.IsPatched = true;
						results.push_back(std::move(entry));
					}
				}
			} while (::Module32NextW(hSnap, &me));
		}

		::CloseHandle(hProc);
		::CloseHandle(hSnap);
		return results;
	});
}

void ProcessSecurityView::BuildModuleStompingTable() {
	if (_stompingScanning) {
		Text("Scanning modules... (comparing in-memory vs on-disk)");
		return;
	}

	if (!_stompedSections.empty())
		TextColored(ImVec4(1.0f, 0.6f, 0.0f, 1.0f), "%zu stomped section(s) found", _stompedSections.size());
	else if (_targetPid > 0)
		TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), "No module stomping detected.");

	if (BeginTable("stompingTable", 5, ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg)) {
		TableSetupScrollFreeze(1, 1);
		TableSetupColumn("Module");
		TableSetupColumn("Section", ImGuiTableColumnFlags_WidthFixed, 80.0f);
		TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 140.0f);
		TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 80.0f);
		TableSetupColumn("Patched Bytes", ImGuiTableColumnFlags_WidthFixed, 100.0f);
		TableHeadersRow();

		for (const auto& entry : _stompedSections) {
			TableNextRow();
			TableSetBgColor(ImGuiTableBgTarget_RowBg0, IM_COL32(180, 100, 0, 60));
			TableSetColumnIndex(0); Text("%s", entry.ModuleName.c_str());
			TableSetColumnIndex(1); Text("%s", entry.SectionName.c_str());
			TableSetColumnIndex(2); Text("0x%llX", entry.MemoryAddress);
			TableSetColumnIndex(3); Text("0x%X", entry.SectionSize);
			TableSetColumnIndex(4); TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "%u", entry.PatchedBytes);
		}
		EndTable();
	}
}

/* =============== Direct Syscall Detection =============== */

void ProcessSecurityView::ScanDirectSyscalls(DWORD pid) {
	if (_syscallScanning) return;
	_selectedDirectSyscall = -1;
	_disasmDirectSyscall = -1;
	_showDirectSyscallDisasm = false;
	_syscallScanning = true;
	_syscallFuture = std::async(std::launch::async, [pid]() -> std::vector<DirectSyscallEntry> {
		std::vector<DirectSyscallEntry> results;
		HANDLE hProc = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
		if (!hProc) return results;

		// Get ntdll range
		HMODULE hNtdll = nullptr;
		MODULEINFO ntdllInfo{};
		{
			HANDLE hSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
			if (hSnap != INVALID_HANDLE_VALUE) {
				MODULEENTRY32W me{};
				me.dwSize = sizeof(me);
				if (::Module32FirstW(hSnap, &me)) {
					do {
						CStringW name(me.szModule);
						name.MakeLower();
						if (name == L"ntdll.dll") {
							hNtdll = me.hModule;
							ntdllInfo.lpBaseOfDll = me.modBaseAddr;
							ntdllInfo.SizeOfImage = me.modBaseSize;
							break;
						}
					} while (::Module32NextW(hSnap, &me));
				}
				::CloseHandle(hSnap);
			}
		}

		unsigned long long ntdllBase = (unsigned long long)ntdllInfo.lpBaseOfDll;
		unsigned long long ntdllEnd = ntdllBase + ntdllInfo.SizeOfImage;

		// Scan all executable memory regions for syscall instructions (0F 05)
		MEMORY_BASIC_INFORMATION mbi{};
		LPVOID addr = nullptr;
		while (::VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
			if (mbi.State == MEM_COMMIT && IsExecuteProtect(mbi.Protect) && mbi.RegionSize < 64 * 1024 * 1024) {
				unsigned long long regionBase = (unsigned long long)mbi.BaseAddress;
				// Skip ntdll itself
				bool isNtdll = (regionBase >= ntdllBase && regionBase < ntdllEnd);

				if (!isNtdll && mbi.RegionSize > 0) {
					std::vector<BYTE> regionData(mbi.RegionSize);
					SIZE_T bytesRead = 0;
					if (::ReadProcessMemory(hProc, mbi.BaseAddress, regionData.data(), mbi.RegionSize, &bytesRead) && bytesRead > 1) {
						for (SIZE_T i = 0; i + 1 < bytesRead; i++) {
							if (regionData[i] == 0x0F && regionData[i + 1] == 0x05) {
								DirectSyscallEntry entry;
								entry.Address = regionBase + i;
								entry.RegionBase = regionBase;
								entry.RegionSize = static_cast<unsigned long>(mbi.RegionSize);
								entry.Protect = mbi.Protect;
								entry.OutsideNtdll = true;

								// Try to identify the module
								WCHAR modName[MAX_PATH]{};
								if (::GetMappedFileNameW(hProc, (LPVOID)(regionBase), modName, MAX_PATH)) {
									int len = ::WideCharToMultiByte(CP_UTF8, 0, modName, -1, nullptr, 0, nullptr, nullptr);
									entry.Module.resize(len > 0 ? len - 1 : 0);
									if (len > 0) ::WideCharToMultiByte(CP_UTF8, 0, modName, -1, entry.Module.data(), len, nullptr, nullptr);
								}
								else {
									entry.Module = "(unbacked)";
								}

								// Check surrounding bytes for mov eax, <syscall_number> pattern
								if (i >= 4 && regionData[i - 4] == 0xB8) {
									unsigned long sysNum = *(unsigned long*)&regionData[i - 3];
									char buf[64];
									sprintf_s(buf, "syscall #%u (mov eax, 0x%X)", sysNum, sysNum);
									entry.Context = buf;
								}
								else {
									entry.Context = "syscall instruction";
								}

								SIZE_T start = i >= 8 ? i - 8 : 0;
								SIZE_T available = bytesRead - start;
								SIZE_T sampleCount = available < 24 ? available : 24;
								entry.ByteCount = static_cast<unsigned int>(sampleCount);
								if (sampleCount > 0) {
									memcpy(entry.Bytes, regionData.data() + start, sampleCount);
									entry.Disassembly = DisassembleBytes(entry.Bytes, entry.ByteCount, regionBase + start);
								}

								results.push_back(std::move(entry));
								if (results.size() > 500) break; // limit results
							}
						}
					}
				}
			}
			addr = (LPBYTE)mbi.BaseAddress + mbi.RegionSize;
			if (results.size() > 500) break;
		}

		::CloseHandle(hProc);
		return results;
	});
}

void ProcessSecurityView::BuildDirectSyscallTable() {
	if (_syscallScanning) {
		Text("Scanning process memory for direct syscall patterns (0F 05)...");
		return;
	}

	if (!_directSyscalls.empty())
		TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "%zu direct syscall(s) outside ntdll!", _directSyscalls.size());
	else if (_targetPid > 0)
		TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), "No direct syscalls found outside ntdll.");

	if (BeginTable("directSyscallTable", 4, ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg)) {
		TableSetupScrollFreeze(1, 1);
		TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 140.0f);
		TableSetupColumn("Module");
		TableSetupColumn("Context");
		TableSetupColumn("Location", ImGuiTableColumnFlags_WidthFixed, 100.0f);
		TableHeadersRow();

		for (int index = 0; index < (int)_directSyscalls.size(); index++) {
			auto& entry = _directSyscalls[index];
			TableNextRow();
			TableSetBgColor(ImGuiTableBgTarget_RowBg0, IM_COL32(180, 40, 40, 60));
			TableSetColumnIndex(0);
			char label[48]{};
			sprintf_s(label, "0x%llX##ds%d", entry.Address, index);
			Selectable(label, _selectedDirectSyscall == index, ImGuiSelectableFlags_SpanAllColumns);
			if (IsItemClicked())
				_selectedDirectSyscall = index;
			if (IsItemHovered() && IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
				_selectedDirectSyscall = index;
				_disasmDirectSyscall = index;
				_showDirectSyscallDisasm = true;
			}
			if (BeginPopupContextItem()) {
				_selectedDirectSyscall = index;
				if (MenuItem("Copy Address")) {
					char buf[32]{};
					sprintf_s(buf, "0x%016llX", entry.Address);
					ImGui::SetClipboardText(buf);
				}
				if (MenuItem("Disassemble")) {
					_disasmDirectSyscall = index;
					_showDirectSyscallDisasm = true;
				}
				EndPopup();
			}
			TableSetColumnIndex(1); Text("%s", entry.Module.c_str());
			TableSetColumnIndex(2); Text("%s", entry.Context.c_str());
			TableSetColumnIndex(3); TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "Outside ntdll");
		}
		EndTable();
	}

	BuildDirectSyscallDetails();
}

void ProcessSecurityView::BuildDirectSyscallDetails() {
	if (_showDirectSyscallDisasm && _disasmDirectSyscall >= 0 && _disasmDirectSyscall < (int)_directSyscalls.size()) {
		OpenPopup("Direct Syscall Disassembly");
		_showDirectSyscallDisasm = false;
	}

	if (BeginPopupModal("Direct Syscall Disassembly", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
		if (_disasmDirectSyscall >= 0 && _disasmDirectSyscall < (int)_directSyscalls.size()) {
			const auto& entry = _directSyscalls[_disasmDirectSyscall];
			Text("Address: 0x%llX", entry.Address);
			Text("Module: %s", entry.Module.c_str());
			Text("Context: %s", entry.Context.c_str());
			Text("Region: 0x%llX (+0x%X)", entry.RegionBase, entry.RegionSize);
			Text("Protection: %s", ProtectToString(entry.Protect).c_str());
			Separator();
			Text("Bytes: %s", FormatBytes(entry.Bytes, entry.ByteCount).c_str());
			Separator();
			TextUnformatted("Disassembly");
			BeginChild("##DirectSyscallDisasmText", ImVec2(620, 140), true);
			TextUnformatted(entry.Disassembly.empty() ? "No disassembly available" : entry.Disassembly.c_str());
			EndChild();
		}
		if (Button("Close"))
			CloseCurrentPopup();
		EndPopup();
	}

	if (_selectedDirectSyscall < 0 || _selectedDirectSyscall >= (int)_directSyscalls.size())
		return;

	const auto& entry = _directSyscalls[_selectedDirectSyscall];
	Separator();
	Text("Direct Syscall Details");
	Separator();
	if (BeginTable("directSyscallDetails", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingFixedFit)) {
		TableSetupColumn("Field", ImGuiTableColumnFlags_WidthFixed, 180.0f);
		TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);

		auto Row = [](const char* field, const char* fmt, ...) {
			TableNextRow();
			TableSetColumnIndex(0);
			TextUnformatted(field);
			TableSetColumnIndex(1);
			va_list args;
			va_start(args, fmt);
			TextV(fmt, args);
			va_end(args);
		};

		Row("Address", "0x%016llX", entry.Address);
		Row("Module", "%s", entry.Module.c_str());
		Row("Context", "%s", entry.Context.c_str());
		Row("Region Base", "0x%016llX", entry.RegionBase);
		Row("Region Size", "0x%X", entry.RegionSize);
		Row("Protection", "%s", ProtectToString(entry.Protect).c_str());
		Row("Bytes", "%s", FormatBytes(entry.Bytes, entry.ByteCount).c_str());

		EndTable();
	}
}

/* =============== Syscall Stub Integrity Check =============== */

void ProcessSecurityView::ScanSyscallStubs(DWORD pid) {
	if (_stubScanning) return;
	_stubScanning = true;
	_stubFuture = std::async(std::launch::async, [pid]() -> std::vector<SyscallStubEntry> {
		std::vector<SyscallStubEntry> results;

		// Load a clean copy of ntdll from disk
		WCHAR ntdllPath[MAX_PATH]{};
		::GetSystemDirectoryW(ntdllPath, MAX_PATH);
		::wcscat_s(ntdllPath, L"\\ntdll.dll");

		HMODULE hDiskNtdll = ::LoadLibraryExW(ntdllPath, nullptr, DONT_RESOLVE_DLL_REFERENCES);
		if (!hDiskNtdll) return results;

		// Get in-memory ntdll of the target process
		HANDLE hProc = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
		if (!hProc) { ::FreeLibrary(hDiskNtdll); return results; }

		HMODULE hRemoteNtdll = nullptr;
		{
			HANDLE hSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
			if (hSnap != INVALID_HANDLE_VALUE) {
				MODULEENTRY32W me{};
				me.dwSize = sizeof(me);
				if (::Module32FirstW(hSnap, &me)) {
					do {
						CStringW name(me.szModule);
						name.MakeLower();
						if (name == L"ntdll.dll") {
							hRemoteNtdll = (HMODULE)me.modBaseAddr;
							break;
						}
					} while (::Module32NextW(hSnap, &me));
				}
				::CloseHandle(hSnap);
			}
		}

		if (!hRemoteNtdll) { ::CloseHandle(hProc); ::FreeLibrary(hDiskNtdll); return results; }

		// Enumerate exports from disk ntdll to find Nt/Zw functions
		auto* dosHeader = (IMAGE_DOS_HEADER*)hDiskNtdll;
		auto* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)hDiskNtdll + dosHeader->e_lfanew);
		auto& exportDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (exportDir.VirtualAddress == 0) { ::CloseHandle(hProc); ::FreeLibrary(hDiskNtdll); return results; }

		auto* exports = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)hDiskNtdll + exportDir.VirtualAddress);
		auto* names = (DWORD*)((BYTE*)hDiskNtdll + exports->AddressOfNames);
		auto* ordinals = (WORD*)((BYTE*)hDiskNtdll + exports->AddressOfNameOrdinals);
		auto* functions = (DWORD*)((BYTE*)hDiskNtdll + exports->AddressOfFunctions);

		for (DWORD i = 0; i < exports->NumberOfNames && i < 4096; i++) {
			const char* funcName = (const char*)((BYTE*)hDiskNtdll + names[i]);
			// Only check Nt* functions (syscall stubs), skip Zw duplicates
			if (funcName[0] != 'N' || funcName[1] != 't') continue;
			if (strncmp(funcName, "Ntdll", 5) == 0) continue;

			DWORD funcRva = functions[ordinals[i]];
			BYTE* diskFunc = (BYTE*)hDiskNtdll + funcRva;
			BYTE* remoteFunc = (BYTE*)hRemoteNtdll + funcRva;

			// Read first 16 bytes from disk and memory
			BYTE diskBytes[16]{};
			BYTE memBytes[16]{};
			memcpy(diskBytes, diskFunc, 16);

			SIZE_T bytesRead = 0;
			if (!::ReadProcessMemory(hProc, remoteFunc, memBytes, 16, &bytesRead) || bytesRead < 16)
				continue;

			bool patched = (memcmp(diskBytes, memBytes, 16) != 0);

			SyscallStubEntry entry;
			entry.FunctionName = funcName;
			entry.Address = (unsigned long long)remoteFunc;
			memcpy(entry.DiskBytes, diskBytes, 16);
			memcpy(entry.MemoryBytes, memBytes, 16);
			entry.IsPatched = patched;

			// Extract service number from disk stub: mov eax, <num> (B8 XX XX XX XX)
			if (diskBytes[0] == 0x4C && diskBytes[3] == 0xB8) {
				entry.ServiceNumber = *(unsigned long*)&diskBytes[4];
			}

			if (patched)
				results.insert(results.begin(), std::move(entry)); // patched entries first
			else
				results.push_back(std::move(entry));
		}

		::CloseHandle(hProc);
		::FreeLibrary(hDiskNtdll);
		return results;
	});
}

void ProcessSecurityView::BuildSyscallStubTable() {
	if (_stubScanning) {
		Text("Comparing ntdll stubs in-memory vs on-disk...");
		return;
	}

	int patchedCount = 0;
	for (auto& e : _syscallStubs) if (e.IsPatched) patchedCount++;

	if (patchedCount > 0)
		TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "%d patched syscall stub(s)!", patchedCount);
	else if (!_syscallStubs.empty())
		TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), "All %zu syscall stubs match disk. No hooks detected.", _syscallStubs.size());

	if (BeginTable("stubTable", 5, ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg)) {
		TableSetupScrollFreeze(1, 1);
		TableSetupColumn("Function");
		TableSetupColumn("SSN", ImGuiTableColumnFlags_WidthFixed, 60.0f);
		TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 140.0f);
		TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed, 80.0f);
		TableSetupColumn("Disk vs Memory Bytes");
		TableHeadersRow();

		for (const auto& entry : _syscallStubs) {
			TableNextRow();
			if (entry.IsPatched) TableSetBgColor(ImGuiTableBgTarget_RowBg0, IM_COL32(180, 40, 40, 60));
			TableSetColumnIndex(0); Text("%s", entry.FunctionName.c_str());
			TableSetColumnIndex(1); Text("0x%X", entry.ServiceNumber);
			TableSetColumnIndex(2); Text("0x%llX", entry.Address);
			TableSetColumnIndex(3);
			if (entry.IsPatched) TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "HOOKED");
			else TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), "Clean");
			TableSetColumnIndex(4);
			if (entry.IsPatched) {
				char buf[128]{};
				sprintf_s(buf, "Disk: %02X %02X %02X %02X | Mem: %02X %02X %02X %02X",
					entry.DiskBytes[0], entry.DiskBytes[1], entry.DiskBytes[2], entry.DiskBytes[3],
					entry.MemoryBytes[0], entry.MemoryBytes[1], entry.MemoryBytes[2], entry.MemoryBytes[3]);
				Text("%s", buf);
			}
			else {
				TextDisabled("Match");
			}
		}
		EndTable();
	}
}

/* =============== Token Manipulation Detection =============== */

void ProcessSecurityView::ScanTokens(DWORD pid) {
	if (_tokenScanning) return;
	_tokenScanning = true;
	_tokenFuture = std::async(std::launch::async, [pid]() -> TokenInfo {
		TokenInfo info{};
		info.ProcessId = pid;

		HANDLE hProc = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
		if (!hProc) return info;

		WCHAR imagePath[MAX_PATH]{};
		DWORD pathSize = MAX_PATH;
		if (::QueryFullProcessImageNameW(hProc, 0, imagePath, &pathSize))
			info.ImageName = WideToUtf8(imagePath);

		HANDLE hToken = nullptr;
		if (!::OpenProcessToken(hProc, TOKEN_QUERY, &hToken)) { ::CloseHandle(hProc); return info; }

		BYTE userBuf[256]{};
		DWORD userSize = 0;
		if (::GetTokenInformation(hToken, TokenUser, userBuf, sizeof(userBuf), &userSize)) {
			auto* tokenUser = (TOKEN_USER*)userBuf;
			WCHAR name[128]{}, domain[128]{};
			DWORD nameLen = 128, domainLen = 128;
			SID_NAME_USE sidUse;
			if (::LookupAccountSidW(nullptr, tokenUser->User.Sid, name, &nameLen, domain, &domainLen, &sidUse))
				info.UserName = WideToUtf8(domain) + "\\" + WideToUtf8(name);
		}

		TOKEN_ELEVATION elevation{};
		DWORD elevSize = 0;
		if (::GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &elevSize))
			info.IsElevated = elevation.TokenIsElevated != 0;

		BYTE integrityBuf[256]{};
		DWORD integritySize = 0;
		if (::GetTokenInformation(hToken, TokenIntegrityLevel, integrityBuf, sizeof(integrityBuf), &integritySize)) {
			auto* tml = (TOKEN_MANDATORY_LABEL*)integrityBuf;
			auto* subAuthCount = ::GetSidSubAuthorityCount(tml->Label.Sid);
			if (subAuthCount && *subAuthCount > 0) {
				info.IntegrityLevel = *::GetSidSubAuthority(tml->Label.Sid, *subAuthCount - 1);
				if (info.IntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID) info.IntegrityString = "System";
				else if (info.IntegrityLevel >= SECURITY_MANDATORY_HIGH_RID) info.IntegrityString = "High";
				else if (info.IntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID) info.IntegrityString = "Medium";
				else if (info.IntegrityLevel >= SECURITY_MANDATORY_LOW_RID) info.IntegrityString = "Low";
				else info.IntegrityString = "Untrusted";
			}
		}

		DWORD sessionId = 0;
		DWORD sessionSize = 0;
		if (::GetTokenInformation(hToken, TokenSessionId, &sessionId, sizeof(sessionId), &sessionSize))
			info.SessionId = sessionId;

		BYTE privBuf[2048]{};
		DWORD privSize = 0;
		if (::GetTokenInformation(hToken, TokenPrivileges, privBuf, sizeof(privBuf), &privSize)) {
			auto* privs = (TOKEN_PRIVILEGES*)privBuf;
			static const char* suspiciousPrivs[] = {
				"SeDebugPrivilege", "SeTcbPrivilege", "SeAssignPrimaryTokenPrivilege",
				"SeLoadDriverPrivilege", "SeBackupPrivilege", "SeRestorePrivilege",
				"SeTakeOwnershipPrivilege", "SeImpersonatePrivilege"
			};

			for (DWORD i = 0; i < privs->PrivilegeCount; i++) {
				WCHAR name[128]{};
				DWORD nameLen = 128;
				if (::LookupPrivilegeNameW(nullptr, &privs->Privileges[i].Luid, name, &nameLen)) {
					auto privName = WideToUtf8(name);
					info.Privileges.push_back(privName);
					if (privs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) {
						info.EnabledPrivileges.push_back(privName);
						for (auto& sp : suspiciousPrivs) {
							if (privName == sp) info.SuspiciousPrivileges = true;
						}
					}
				}
			}
		}

		TOKEN_TYPE tokenType;
		DWORD typeSize = 0;
		if (::GetTokenInformation(hToken, TokenType, &tokenType, sizeof(tokenType), &typeSize))
			info.IsImpersonating = (tokenType == TokenImpersonation);

		::CloseHandle(hToken);
		::CloseHandle(hProc);
		return info;
	});
}

void ProcessSecurityView::BuildTokenPanel() {
	if (_tokenScanning) {
		Text("Inspecting token state...");
		return;
	}
	if (_tokenInfo.ProcessId == 0) {
		TextDisabled("Token data is not available yet for this process.");
		return;
	}

	Text("Process: %s (PID %u)", _tokenInfo.ImageName.c_str(), _tokenInfo.ProcessId);
	Text("User: %s", _tokenInfo.UserName.c_str());
	Text("Session: %u", _tokenInfo.SessionId);
	Text("Integrity: %s (0x%X)", _tokenInfo.IntegrityString.c_str(), _tokenInfo.IntegrityLevel);
	Text("Elevated: %s", _tokenInfo.IsElevated ? "Yes" : "No");
	Text("Impersonating: %s", _tokenInfo.IsImpersonating ? "YES" : "No");

	if (_tokenInfo.SuspiciousPrivileges)
		TextColored(ImVec4(1.0f, 0.6f, 0.0f, 1.0f), "Suspicious enabled privileges detected");

	Separator();
	Text("Enabled Privileges (%zu):", _tokenInfo.EnabledPrivileges.size());
	for (auto& p : _tokenInfo.EnabledPrivileges) {
		bool isSuspicious = (p == "SeDebugPrivilege" || p == "SeTcbPrivilege" || p == "SeLoadDriverPrivilege" ||
			p == "SeAssignPrimaryTokenPrivilege" || p == "SeImpersonatePrivilege");
		if (isSuspicious)
			TextColored(ImVec4(1.0f, 0.6f, 0.0f, 1.0f), "  %s", p.c_str());
		else
			Text("  %s", p.c_str());
	}

	Separator();
	char treeLabel[64]{};
	sprintf_s(treeLabel, "All Privileges (%zu)", _tokenInfo.Privileges.size());
	if (TreeNode(treeLabel)) {
		for (auto& p : _tokenInfo.Privileges)
			BulletText("%s", p.c_str());
		TreePop();
	}
}

/* =============== Debug Object Detection =============== */

void ProcessSecurityView::ScanDebugObjects() {
	if (_debugScanning) return;
	_debugScanning = true;
	_debugFuture = std::async(std::launch::async, []() -> std::vector<DebugObjectEntry> {
		std::vector<DebugObjectEntry> results;
		auto NtQIP = GetNtQueryInformationProcess();
		if (!NtQIP) return results;

		DWORD pids[4096]{};
		DWORD bytesReturned = 0;
		if (!::EnumProcesses(pids, sizeof(pids), &bytesReturned)) return results;
		DWORD count = bytesReturned / sizeof(DWORD);

		for (DWORD i = 0; i < count; i++) {
			if (pids[i] == 0) continue;
			HANDLE hProc = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pids[i]);
			if (!hProc) continue;

			DebugObjectEntry entry;
			entry.ProcessId = pids[i];

			WCHAR imagePath[MAX_PATH]{};
			DWORD pathSize = MAX_PATH;
			if (::QueryFullProcessImageNameW(hProc, 0, imagePath, &pathSize)) {
				auto* name = wcsrchr(imagePath, L'\\');
				entry.ImageName = WideToUtf8(name ? name + 1 : imagePath);
			}

			HANDLE debugObj = nullptr;
			ULONG retLen = 0;
			auto status = NtQIP(hProc, (PROCESSINFOCLASS)30, &debugObj, sizeof(debugObj), &retLen);
			entry.HasDebugObject = (status == 0 && debugObj != nullptr);
			if (entry.HasDebugObject && debugObj) ::CloseHandle(debugObj);

			ULONG_PTR debugPort = 0;
			status = NtQIP(hProc, (PROCESSINFOCLASS)7, &debugPort, sizeof(debugPort), &retLen);
			entry.HasDebugPort = (status == 0 && debugPort != 0);

			if (entry.HasDebugObject || entry.HasDebugPort)
				results.push_back(std::move(entry));

			::CloseHandle(hProc);
		}

		return results;
	});
}

void ProcessSecurityView::BuildDebugObjectTable() {
	if (_debugScanning) {
		Text("Enumerating debug objects...");
		return;
	}
	if (!_debugObjects.empty())
		TextColored(ImVec4(1.0f, 0.6f, 0.0f, 1.0f), "%zu process(es) with debug objects attached", _debugObjects.size());
	else
		TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), "No processes with debug objects found.");
	Separator();

	if (BeginTable("debugObjTable", 4, ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg)) {
		TableSetupScrollFreeze(1, 1);
		TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 60.0f);
		TableSetupColumn("Image Name");
		TableSetupColumn("Debug Object", ImGuiTableColumnFlags_WidthFixed, 100.0f);
		TableSetupColumn("Debug Port", ImGuiTableColumnFlags_WidthFixed, 100.0f);
		TableHeadersRow();

		for (const auto& entry : _debugObjects) {
			TableNextRow();
			TableSetColumnIndex(0); Text("%u", entry.ProcessId);
			TableSetColumnIndex(1); Text("%s", entry.ImageName.c_str());
			TableSetColumnIndex(2); Text("%s", entry.HasDebugObject ? "Yes" : "No");
			TableSetColumnIndex(3); Text("%s", entry.HasDebugPort ? "Yes" : "No");
		}
		EndTable();
	}
}

/* =============== Hypervisor Presence Detection =============== */

void ProcessSecurityView::ScanHypervisor() {
	_hypervisorInfo = {};

	// CPUID leaf 1, ECX bit 31 = hypervisor present
	int cpuInfo[4]{};
	__cpuid(cpuInfo, 1);
	_hypervisorInfo.HypervisorPresent = (cpuInfo[2] & (1 << 31)) != 0;

	if (_hypervisorInfo.HypervisorPresent) {
		// CPUID leaf 0x40000000 = hypervisor vendor
		__cpuid(cpuInfo, 0x40000000);
		char vendor[13]{};
		memcpy(vendor, &cpuInfo[1], 4);
		memcpy(vendor + 4, &cpuInfo[2], 4);
		memcpy(vendor + 8, &cpuInfo[3], 4);
		_hypervisorInfo.VendorId = vendor;
	}

	// Timing-based detection: measure RDTSC around CPUID
	constexpr int iterations = 100;
	unsigned long long totalRdtsc = 0, totalCpuid = 0;
	for (int i = 0; i < iterations; i++) {
		unsigned long long start = __rdtsc();
		unsigned long long end = __rdtsc();
		totalRdtsc += (end - start);

		start = __rdtsc();
		__cpuid(cpuInfo, 0);
		end = __rdtsc();
		totalCpuid += (end - start);
	}
	_hypervisorInfo.AvgRdtscCycles = totalRdtsc / iterations;
	_hypervisorInfo.AvgCpuidCycles = totalCpuid / iterations;
	_hypervisorInfo.TimingAnomaly = (_hypervisorInfo.AvgCpuidCycles > 500); // Typical bare metal is ~100-200 cycles
	_hypervisorInfo.Scanned = true;
}

void ProcessSecurityView::BuildHypervisorPanel() {
	if (!_hypervisorInfo.Scanned) {
		TextDisabled("Hypervisor data is not available yet.");
		return;
	}

	Text("Hypervisor Present (CPUID): %s", _hypervisorInfo.HypervisorPresent ? "YES" : "No");
	if (_hypervisorInfo.HypervisorPresent)
		Text("Hypervisor Vendor: %s", _hypervisorInfo.VendorId.c_str());

	Separator();
	Text("Timing Analysis:");
	Text("  Avg RDTSC-RDTSC: %llu cycles", _hypervisorInfo.AvgRdtscCycles);
	Text("  Avg CPUID cycles: %llu cycles", _hypervisorInfo.AvgCpuidCycles);

	if (_hypervisorInfo.TimingAnomaly)
		TextColored(ImVec4(1.0f, 0.6f, 0.0f, 1.0f), "Timing anomaly detected: CPUID takes >500 cycles (possible VM interception)");
	else
		TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), "No significant timing anomaly.");

	Separator();
	TextDisabled("Note: Timing thresholds are heuristic. Results may vary by CPU.");
}

/* =============== Job Object Inspector =============== */

void ProcessSecurityView::ScanJobObjects(DWORD pid) {
	if (_jobScanning) return;
	_jobScanning = true;
	_jobFuture = std::async(std::launch::async, [pid]() -> JobObjectInfo {
		JobObjectInfo info{};
		info.ProcessId = pid;

		HANDLE hProc = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
		if (!hProc) return info;

		BOOL inJob = FALSE;
		::IsProcessInJob(hProc, nullptr, &inJob);
		info.InJob = inJob != FALSE;

		WCHAR imagePath[MAX_PATH]{};
		DWORD pathSize = MAX_PATH;
		if (::QueryFullProcessImageNameW(hProc, 0, imagePath, &pathSize)) {
			auto* name = wcsrchr(imagePath, L'\\');
			info.ImageName = WideToUtf8(name ? name + 1 : imagePath);
		}

		if (info.InJob) {
			JOBOBJECT_BASIC_ACCOUNTING_INFORMATION acctInfo{};
			if (::QueryInformationJobObject(nullptr, JobObjectBasicAccountingInformation, &acctInfo, sizeof(acctInfo), nullptr)) {
				info.ActiveProcesses = acctInfo.ActiveProcesses;
				info.TotalProcesses = acctInfo.TotalProcesses;
			}

			JOBOBJECT_EXTENDED_LIMIT_INFORMATION extInfo{};
			if (::QueryInformationJobObject(nullptr, JobObjectExtendedLimitInformation, &extInfo, sizeof(extInfo), nullptr)) {
				info.ProcessMemoryLimit = extInfo.ProcessMemoryLimit;
				info.JobMemoryLimit = extInfo.JobMemoryLimit;
				if (extInfo.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_ACTIVE_PROCESS)
					info.ActiveProcessLimit = extInfo.BasicLimitInformation.ActiveProcessLimit;
			}

			JOBOBJECT_BASIC_UI_RESTRICTIONS uiInfo{};
			if (::QueryInformationJobObject(nullptr, JobObjectBasicUIRestrictions, &uiInfo, sizeof(uiInfo), nullptr))
				info.UIRestrictions = uiInfo.UIRestrictionsClass;
		}

		::CloseHandle(hProc);
		return info;
	});
}

void ProcessSecurityView::BuildJobObjectPanel() {
	if (_jobScanning) {
		Text("Inspecting job object state...");
		return;
	}
	if (_jobInfo.ProcessId == 0) {
		TextDisabled("Job object data is not available yet for this process.");
		return;
	}

	Text("Process: %s (PID %u)", _jobInfo.ImageName.c_str(), _jobInfo.ProcessId);
	Text("In Job: %s", _jobInfo.InJob ? "YES" : "No");

	if (!_jobInfo.InJob) {
		TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), "Process is not running inside a job object.");
		return;
	}

	Separator();
	TextColored(ImVec4(1.0f, 0.6f, 0.0f, 1.0f), "Process is running inside a job object (sandbox/EDR restriction)");
	Text("Active Processes: %u", _jobInfo.ActiveProcesses);
	Text("Total Processes: %u", _jobInfo.TotalProcesses);
	if (_jobInfo.ActiveProcessLimit > 0)
		Text("Active Process Limit: %u", _jobInfo.ActiveProcessLimit);
	if (_jobInfo.ProcessMemoryLimit > 0)
		Text("Process Memory Limit: %llu bytes", _jobInfo.ProcessMemoryLimit);
	if (_jobInfo.JobMemoryLimit > 0)
		Text("Job Memory Limit: %llu bytes", _jobInfo.JobMemoryLimit);
	if (_jobInfo.UIRestrictions != 0) {
		Text("UI Restrictions: 0x%X", _jobInfo.UIRestrictions);
		if (_jobInfo.UIRestrictions & JOB_OBJECT_UILIMIT_DESKTOP) BulletText("Desktop access restricted");
		if (_jobInfo.UIRestrictions & JOB_OBJECT_UILIMIT_DISPLAYSETTINGS) BulletText("Display settings restricted");
		if (_jobInfo.UIRestrictions & JOB_OBJECT_UILIMIT_EXITWINDOWS) BulletText("Exit windows restricted");
		if (_jobInfo.UIRestrictions & JOB_OBJECT_UILIMIT_GLOBALATOMS) BulletText("Global atoms restricted");
		if (_jobInfo.UIRestrictions & JOB_OBJECT_UILIMIT_HANDLES) BulletText("Handle access restricted");
		if (_jobInfo.UIRestrictions & JOB_OBJECT_UILIMIT_READCLIPBOARD) BulletText("Clipboard read restricted");
		if (_jobInfo.UIRestrictions & JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS) BulletText("System parameters restricted");
		if (_jobInfo.UIRestrictions & JOB_OBJECT_UILIMIT_WRITECLIPBOARD) BulletText("Clipboard write restricted");
	}
}

/* =============== CFG Status =============== */

void ProcessSecurityView::ScanCfgStatus(DWORD pid) {
	if (_cfgScanning) return;
	_cfgScanning = true;
	_cfgFuture = std::async(std::launch::async, [pid]() -> CfgInfo {
		CfgInfo info{};
		info.ProcessId = pid;

		auto NtQIP = GetNtQueryInformationProcess();
		if (!NtQIP) return info;

		HANDLE hProc = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
		if (!hProc) return info;

		struct {
			DWORD EnableControlFlowGuard : 1;
			DWORD EnableExportSuppression : 1;
			DWORD StrictMode : 1;
			DWORD EnableXfg : 1;
			DWORD EnableXfgAuditMode : 1;
			DWORD ReservedFlags : 27;
		} cfgPolicy{};

		if (::GetProcessMitigationPolicy(hProc, ProcessControlFlowGuardPolicy, &cfgPolicy, sizeof(cfgPolicy))) {
			info.CfgEnabled = cfgPolicy.EnableControlFlowGuard != 0;
			info.CfgStrictMode = cfgPolicy.StrictMode != 0;
			info.CfgExportSuppression = cfgPolicy.EnableExportSuppression != 0;
			info.XfgEnabled = cfgPolicy.EnableXfg != 0;
			info.XfgAuditMode = cfgPolicy.EnableXfgAuditMode != 0;
		}

		info.Scanned = true;
		::CloseHandle(hProc);
		return info;
	});
}

void ProcessSecurityView::BuildCfgPanel() {
	if (_cfgScanning) {
		Text("Checking process mitigation policy...");
		return;
	}
	if (!_cfgInfo.Scanned) {
		TextDisabled("CFG status is not available yet for this process.");
		return;
	}

	Text("Process PID: %u", _cfgInfo.ProcessId);
	Separator();
	Text("Control Flow Guard (CFG): %s", _cfgInfo.CfgEnabled ? "ENABLED" : "Disabled");
	if (_cfgInfo.CfgEnabled)
		TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), "  CFG is active - indirect calls are validated");
	else
		TextColored(ImVec4(1.0f, 0.6f, 0.0f, 1.0f), "  CFG is not active");

	Text("CFG Strict Mode: %s", _cfgInfo.CfgStrictMode ? "Yes" : "No");
	Text("Export Suppression: %s", _cfgInfo.CfgExportSuppression ? "Yes" : "No");
	Text("XFG (eXtended Flow Guard): %s", _cfgInfo.XfgEnabled ? "ENABLED" : "Disabled");
	Text("XFG Audit Mode: %s", _cfgInfo.XfgAuditMode ? "Yes" : "No");
}
