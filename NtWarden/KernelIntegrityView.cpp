#include "pch.h"
#include "imgui.h"
#include "KernelIntegrityView.h"
#include "LoggerView.h"
#include "RemoteClient.h"
#include <winternl.h>

#pragma comment(lib, "Ntdll.lib")

using namespace ImGui;

typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(ULONG, PVOID, ULONG, PULONG);

static NtQuerySystemInformation_t GetNtQSI() {
	static auto fn = (NtQuerySystemInformation_t)::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
	return fn;
}

KernelIntegrityView::KernelIntegrityView() : ViewBase(0) {}

void KernelIntegrityView::RefreshNow() { _scanned = false; ScanKernelIntegrity(); _scanned = true; MarkUpdated(); }

void KernelIntegrityView::BuildWindow() { BuildKernelIntegrityTable(); }

void KernelIntegrityView::ScanKernelIntegrity() {
	_kernelIntegrity.clear();

	if (RemoteClient::IsConnected()) {
		auto entries = RemoteClient::GetKernelIntegrity();
		for (auto& e : entries) {
			KernelIntegrityEntry entry;
			entry.FunctionName = e.FunctionName;
			entry.Address = e.FunctionAddress;
			memcpy(entry.ExpectedBytes, &e.ExpectedFirstBytes, 8);
			memcpy(entry.ActualBytes, &e.ActualFirstBytes, 8);
			entry.IsPatched = (e.ExpectedFirstBytes != e.ActualFirstBytes) && (e.ActualFirstBytes != 0);
			_kernelIntegrity.push_back(std::move(entry));
		}
	LoggerView::AddLog(LoggerView::UserModeLog, "Kernel integrity (remote): %zu functions received", _kernelIntegrity.size());
		return;
	}

	auto NtQSI = GetNtQSI();
	if (!NtQSI) return;

	ULONG size = 0;
	NtQSI(11, nullptr, 0, &size);
	if (size == 0) return;

	struct RTL_PROCESS_MODULE_INFORMATION {
		HANDLE Section;
		PVOID MappedBase;
		PVOID ImageBase;
		ULONG ImageSize;
		ULONG Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT OffsetToFileName;
		UCHAR FullPathName[256];
	};
	struct RTL_PROCESS_MODULES {
		ULONG NumberOfModules;
		RTL_PROCESS_MODULE_INFORMATION Modules[1];
	};

	std::vector<BYTE> modBuf(size + 4096);
	if (NtQSI(11, modBuf.data(), (ULONG)modBuf.size(), &size) != 0) return;

	auto* mods = (RTL_PROCESS_MODULES*)modBuf.data();
	if (mods->NumberOfModules == 0) return;

	auto& kernel = mods->Modules[0];
	std::string kernelPath = (char*)kernel.FullPathName;

	std::wstring wKernelPath;
	if (kernelPath.find("\\SystemRoot\\") == 0) {
		WCHAR winDir[MAX_PATH]{};
		::GetWindowsDirectoryW(winDir, MAX_PATH);
		wKernelPath = std::wstring(winDir) + L"\\" + std::wstring(kernelPath.begin() + 12, kernelPath.end());
	}
	else {
		wKernelPath.assign(kernelPath.begin(), kernelPath.end());
	}

	HMODULE hDiskKernel = ::LoadLibraryExW(wKernelPath.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);
	if (!hDiskKernel) return;

	static const char* criticalFunctions[] = {
		"KiSystemCall64",
		"NtCreateFile",
		"NtWriteFile",
		"NtReadFile",
		"NtDeviceIoControlFile",
		"NtOpenProcess",
		"NtCreateThreadEx",
		"NtAllocateVirtualMemory",
		"NtProtectVirtualMemory",
		"NtWriteVirtualMemory",
		"NtMapViewOfSection",
		"PsSetCreateProcessNotifyRoutine",
		"PsSetLoadImageNotifyRoutine",
		"ObRegisterCallbacks",
	};

	for (auto* funcName : criticalFunctions) {
		auto* diskFunc = (BYTE*)::GetProcAddress(hDiskKernel, funcName);
		if (!diskFunc) continue;

		KernelIntegrityEntry entry;
		entry.FunctionName = funcName;
		DWORD rva = (DWORD)((BYTE*)diskFunc - (BYTE*)hDiskKernel);
		entry.Address = (unsigned long long)kernel.ImageBase + rva;
		memcpy(entry.ExpectedBytes, diskFunc, 8);
		memset(entry.ActualBytes, 0, 8);
		entry.IsPatched = false;

		_kernelIntegrity.push_back(std::move(entry));
	}

	::FreeLibrary(hDiskKernel);
	LoggerView::AddLog(LoggerView::UserModeLog, "Kernel integrity: %zu functions checked (disk-side only)", _kernelIntegrity.size());
}

void KernelIntegrityView::BuildKernelIntegrityTable() {
	if (!_scanned) { ScanKernelIntegrity(); _scanned = true; }
	if (_kernelIntegrity.empty()) return;

	int patchedCount = 0;
	for (auto& e : _kernelIntegrity) if (e.IsPatched) patchedCount++;

	if (patchedCount > 0)
		TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "%d kernel function(s) appear patched!", patchedCount);
	else
		Text("%zu kernel functions resolved (disk reference loaded).", _kernelIntegrity.size());

	TextDisabled("Note: Full in-memory comparison requires kernel driver IOCTL support.");

	if (BeginTable("kernIntegrityTable", 4, ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg)) {
		TableSetupScrollFreeze(1, 1);
		TableSetupColumn("Function");
		TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 140.0f);
		TableSetupColumn("Disk Bytes");
		TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed, 80.0f);
		TableHeadersRow();

		for (const auto& entry : _kernelIntegrity) {
			TableNextRow();
			if (entry.IsPatched) TableSetBgColor(ImGuiTableBgTarget_RowBg0, IM_COL32(180, 40, 40, 60));
			TableSetColumnIndex(0); Text("%s", entry.FunctionName.c_str());
			TableSetColumnIndex(1); Text("0x%llX", entry.Address);
			TableSetColumnIndex(2);
			Text("%02X %02X %02X %02X %02X %02X %02X %02X",
				entry.ExpectedBytes[0], entry.ExpectedBytes[1], entry.ExpectedBytes[2], entry.ExpectedBytes[3],
				entry.ExpectedBytes[4], entry.ExpectedBytes[5], entry.ExpectedBytes[6], entry.ExpectedBytes[7]);
			TableSetColumnIndex(3);
			if (entry.IsPatched) TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "PATCHED");
			else TextDisabled("Disk ref");
		}
		EndTable();
	}
}
