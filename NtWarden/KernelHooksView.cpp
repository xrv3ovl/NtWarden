#include "pch.h"
#include "KernelHooksView.h"
#include "DriverHelper.h"
#include "RemoteClient.h"
#include "ImGuiExt.h"
#include "LoggerView.h"
#include "imgui.h"

#include <algorithm>
#include <string_view>

namespace {
	struct NtServiceEntry {
		unsigned long Id;
		const char* Name;
	};

	// Storage for remote function names (must outlive NtServiceEntry pointers)
	static std::vector<std::string> s_remoteNames;

	std::vector<NtServiceEntry> EnumNtServices() {
		std::vector<NtServiceEntry> items;

		if (RemoteClient::IsConnected()) {
			auto remote = RemoteClient::GetNtdllFunctions();
			s_remoteNames.clear();
			s_remoteNames.reserve(remote.size());
			for (const auto& fn : remote)
				s_remoteNames.push_back(fn.Name);
			for (size_t i = 0; i < remote.size(); i++)
				items.push_back({ remote[i].ServiceId, s_remoteNames[i].c_str() });
			std::sort(items.begin(), items.end(), [](const auto& a, const auto& b) { return a.Id < b.Id; });
			return items;
		}

		auto ntdll = ::GetModuleHandleW(L"ntdll.dll");
		if (!ntdll)
			return items;

		auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(ntdll);
		if (dos->e_magic != IMAGE_DOS_SIGNATURE)
			return items;
		auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE*>(ntdll) + dos->e_lfanew);
		if (nt->Signature != IMAGE_NT_SIGNATURE)
			return items;

		auto exportDirRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		if (!exportDirRva)
			return items;

		auto exports = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<BYTE*>(ntdll) + exportDirRva);
		auto functions = reinterpret_cast<PDWORD>(reinterpret_cast<BYTE*>(ntdll) + exports->AddressOfFunctions);
		auto names = reinterpret_cast<PDWORD>(reinterpret_cast<BYTE*>(ntdll) + exports->AddressOfNames);
		auto ordinals = reinterpret_cast<PWORD>(reinterpret_cast<BYTE*>(ntdll) + exports->AddressOfNameOrdinals);

		for (DWORD i = 0; i < exports->NumberOfNames; i++) {
			auto svcName = reinterpret_cast<const char*>(reinterpret_cast<BYTE*>(ntdll) + names[i]);
			if (::strncmp(svcName, "Zw", 2) != 0)
				continue;
			auto stub = reinterpret_cast<const BYTE*>(reinterpret_cast<BYTE*>(ntdll) + functions[ordinals[i]]);
			for (int off = 0; off < 16; off++) {
				if (stub[off] == 0xB8) {
					items.push_back({ *reinterpret_cast<const unsigned long*>(stub + off + 1), svcName });
					break;
				}
			}
		}

		std::sort(items.begin(), items.end(), [](const auto& a, const auto& b) { return a.Id < b.Id; });
		return items;
	}

	bool IsExpectedKernelOwner(std::string_view name) {
		static constexpr std::string_view expected[] = {
			"ntoskrnl.exe", "ntkrnlmp.exe", "ntkrnlpa.exe", "ntkrpamp.exe"
		};
		for (auto candidate : expected) {
			if (_stricmp(name.data(), candidate.data()) == 0)
				return true;
		}
		return false;
	}
}

KernelHooksView::ScanResult KernelHooksView::RefreshAsync() {
	ScanResult result;

	bool remote = RemoteClient::IsConnected();
	auto services = EnumNtServices();
	auto table = remote ? RemoteClient::GetSSDT() : DriverHelper::GetSSDT();

	unsigned long moduleCount = 0;
	bool snapshotOk = remote ? RemoteClient::CreateModuleSnapshot(moduleCount) : DriverHelper::CreateModuleSnapshot(moduleCount);
	if (!snapshotOk) {
		LoggerView::AddLog(LoggerView::UserModeLog, "Kernel Hooks: failed to create module snapshot");
		return result;
	}

	std::vector<KERNEL_MODULE_ENTRY> modules;
	modules.reserve(moduleCount);
	constexpr unsigned long pageSize = 64;
	std::vector<KERNEL_MODULE_ENTRY> page(pageSize);
	for (unsigned long start = 0; start < moduleCount; start += pageSize) {
		unsigned long returned = 0;
		auto requestCount = (std::min)(pageSize, moduleCount - start);
		bool pageOk = remote
			? RemoteClient::QueryModulePage(start, requestCount, page.data(), returned)
			: DriverHelper::QueryModulePage(start, requestCount, page.data(), returned);
		if (!pageOk)
			break;
		for (unsigned long i = 0; i < returned; i++)
			modules.push_back(page[i]);
	}
	if (remote)
		RemoteClient::ReleaseModuleSnapshot();
	else
		DriverHelper::ReleaseModuleSnapshot();

	for (const auto& svc : services) {
		if (svc.Id >= 500)
			continue;

		HookEntry item{};
		item.Id = svc.Id;
		item.Name = svc.Name;
		item.Address = table[svc.Id];

		const KERNEL_MODULE_ENTRY* owner = nullptr;
		for (const auto& mod : modules) {
			auto start = mod.ImageBase;
			auto end = mod.ImageBase + mod.ImageSize;
			if (item.Address >= start && item.Address < end) {
				owner = &mod;
				break;
			}
		}

		if (owner) {
			item.Owner = owner->Name;
			if (!IsExpectedKernelOwner(item.Owner)) {
				item.Suspicious = true;
				item.Reason = "service points outside the kernel image";
			}
		}
		else {
			item.Owner = "<unknown>";
			item.Suspicious = true;
			item.Reason = "service address is outside any loaded kernel module";
		}

		if (item.Suspicious)
			result.suspiciousCount++;
		result.entries.push_back(std::move(item));
	}

	LoggerView::AddLog(LoggerView::UserModeLog, "Kernel Hooks: analyzed %zu SSDT entries, suspicious=%d", result.entries.size(), result.suspiciousCount);
	return result;
}

void KernelHooksView::Refresh() {
	if (_loading)
		return;
	_loading = true;
	LoggerView::AddLog(LoggerView::UserModeLog, "Kernel Hooks: Starting async SSDT analysis...");
	_scanFuture = std::async(std::launch::async, RefreshAsync);
}

void KernelHooksView::BuildWindow() {
	// Poll async scan
	if (_loading && _scanFuture.valid() &&
		_scanFuture.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
		try {
			auto result = _scanFuture.get();
			_entries = std::move(result.entries);
			_suspiciousCount = result.suspiciousCount;
			_loaded = true;
		}
		catch (...) {
			_loadFailed = true;
		LoggerView::AddLog(LoggerView::UserModeLog, "Kernel Hooks: async scan threw an exception");
		}
		_loading = false;
	}

	if (!_loaded && !_loading && !_loadFailed)
		Refresh();

	if (_loading) {
		ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "Analyzing SSDT entries...");
		return;
	}

	ImGui::Text("Entries: %zu", _entries.size());
	ImGui::SameLine();
	if (_suspiciousCount)
		ImGui::TextColored(ImVec4(1.0f, 0.45f, 0.35f, 1.0f), "Suspicious: %d", _suspiciousCount);
	else
		ImGui::TextColored(ImVec4(0.4f, 0.9f, 0.4f, 1.0f), "Suspicious: 0");
	ImGui::Separator();
	ImGui::TextWrapped("Current driver support covers SSDT target ownership checks. Inline, IRP, and Fast I/O hook scans still require extra KWinSys driver IOCTL work.");

	if (ImGui::BeginTable("##KernelHooks", 5,
		ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable |
		ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit, ImVec2(0, ImGui::GetTextLineHeightWithSpacing() * 24))) {
		ImGui::TableSetupScrollFreeze(0, 1);
		ImGui::TableSetupColumn("ID", 0, 60);
		ImGui::TableSetupColumn("Service", 0, 220);
		ImGui::TableSetupColumn("Address", 0, 140);
		ImGui::TableSetupColumn("Owner", 0, 180);
		ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthStretch);
		ImGui::TableHeadersRow();

		ImGuiListClipper clipper;
		clipper.Begin(static_cast<int>(_entries.size()));
		while (clipper.Step()) {
			for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
				const auto& item = _entries[i];
				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0);
				ImGui::Text("%lu", item.Id);
				ImGui::TableSetColumnIndex(1);
				ImGui::TextUnformatted(item.Name.c_str());
				ImGui::TableSetColumnIndex(2);
				ImGui::Text("0x%llX", item.Address);
				ImGui::TableSetColumnIndex(3);
				ImGui::TextUnformatted(item.Owner.c_str());
				ImGui::TableSetColumnIndex(4);
				if (item.Suspicious)
					ImGui::TextColored(ImVec4(1.0f, 0.45f, 0.35f, 1.0f), "%s", item.Reason.c_str());
				else
					ImGui::TextColored(ImVec4(0.4f, 0.9f, 0.4f, 1.0f), "kernel-owned");
			}
		}
		ImGui::EndTable();
	}
}

void KernelHooksView::RefreshNow() {
	_loaded = false;
	_loadFailed = false;
	Refresh();
}
