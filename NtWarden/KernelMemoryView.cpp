#include "pch.h"
#include "KernelMemoryView.h"

#include "FormatHelper.h"
#include "ImGuiExt.h"
#include "NativeSystem.h"
#include "RemoteClient.h"
#include "LoggerView.h"

namespace {
	std::vector<BYTE> QuerySystemInfoBuffer(SYSTEM_INFORMATION_CLASS infoClass) {
		ULONG size = 1 << 16;
		for (int i = 0; i < 8; i++) {
			std::vector<BYTE> buffer(size);
			ULONG returnLength = 0;
			auto status = ::NtQuerySystemInformation(infoClass, buffer.data(), size, &returnLength);
			if (NT_SUCCESS(status)) {
				buffer.resize(returnLength ? returnLength : size);
				return buffer;
			}
			if (status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL)
				break;
			size = returnLength ? returnLength + 4096 : size * 2;
		}
		return {};
	}

	std::string MakeTagString(const UCHAR tag[4]) {
		char buffer[5]{};
		for (int i = 0; i < 4; i++) {
			auto ch = static_cast<char>(tag[i]);
			buffer[i] = ch >= 32 && ch <= 126 ? ch : '.';
		}
		return buffer;
	}

}

KernelMemoryView::KernelMemoryView() : ViewBase(5000) {
}

void KernelMemoryView::Refresh() {
	_bigPool.clear();
	_poolTags.clear();

	if (RemoteClient::IsConnected()) {
		auto remoteBigPool = RemoteClient::GetBigPool();
		_bigPool.reserve(remoteBigPool.size());
		for (const auto& entry : remoteBigPool) {
			BigPoolRow row{};
			row.VirtualAddress = entry.VirtualAddress;
			row.SizeInBytes = entry.SizeInBytes;
			row.Tag = entry.Tag;
			row.NonPaged = entry.NonPaged != 0;
			row.Executable = row.NonPaged && row.SizeInBytes >= 0x1000;
			_bigPool.push_back(std::move(row));
		}

		auto remotePoolTags = RemoteClient::GetPoolTags();
		_poolTags.reserve(remotePoolTags.size());
		for (const auto& entry : remotePoolTags) {
			PoolTagRow row{};
			row.Tag = entry.Tag;
			row.PagedAllocs = static_cast<ULONG>(entry.PagedAllocs);
			row.PagedFrees = static_cast<ULONG>(entry.PagedFrees);
			row.PagedUsed = entry.PagedUsed;
			row.NonPagedAllocs = static_cast<ULONG>(entry.NonPagedAllocs);
			row.NonPagedFrees = static_cast<ULONG>(entry.NonPagedFrees);
			row.NonPagedUsed = entry.NonPagedUsed;
			_poolTags.push_back(std::move(row));
		}
	}
	else {
		if (auto buffer = QuerySystemInfoBuffer(SystemBigPoolInformationClass); !buffer.empty()) {
			auto info = reinterpret_cast<PSYSTEM_BIGPOOL_INFORMATION>(buffer.data());
			_bigPool.reserve(info->Count);
			for (ULONG i = 0; i < info->Count; i++) {
				const auto& entry = info->AllocatedInfo[i];
				BigPoolRow row{};
				row.VirtualAddress = static_cast<ULONG64>(entry.VirtualAddressAndFlags & ~static_cast<ULONG_PTR>(1));
				row.SizeInBytes = static_cast<ULONG64>(entry.SizeInBytes);
				row.Tag = MakeTagString(entry.Tag);
				row.NonPaged = (entry.VirtualAddressAndFlags & 1ull) != 0;
				row.Executable = row.NonPaged && row.SizeInBytes >= 0x1000;
				_bigPool.push_back(std::move(row));
			}
		}

		if (auto buffer = QuerySystemInfoBuffer(SystemPoolTagInformationClass); !buffer.empty()) {
			auto info = reinterpret_cast<PSYSTEM_POOLTAG_INFORMATION>(buffer.data());
			_poolTags.reserve(info->Count);
			for (ULONG i = 0; i < info->Count; i++) {
				const auto& entry = info->TagInfo[i];
				PoolTagRow row{};
				row.Tag = MakeTagString(entry.Tag);
				row.PagedAllocs = entry.PagedAllocs;
				row.PagedFrees = entry.PagedFrees;
				row.PagedUsed = static_cast<ULONG64>(entry.PagedUsed);
				row.NonPagedAllocs = entry.NonPagedAllocs;
				row.NonPagedFrees = entry.NonPagedFrees;
				row.NonPagedUsed = static_cast<ULONG64>(entry.NonPagedUsed);
				_poolTags.push_back(std::move(row));
			}
		}
	}

	ULONG64 executableBytes = 0;
	ULONG64 nonPagedBytes = 0;
	for (const auto& row : _bigPool) {
		if (row.NonPaged)
			nonPagedBytes += row.SizeInBytes;
		if (row.Executable)
			executableBytes += row.SizeInBytes;
	}

	LoggerView::AddLog(LoggerView::UserModeLog, "Enumerated %zu big pool entries, %zu pool tags", _bigPool.size(), _poolTags.size());
}

void KernelMemoryView::BuildWindow() {
	BuildToolBar();

	if (IsUpdateDue()) {
		Refresh();
		MarkUpdated();
	}

	BuildSummary();
	ImGui::Separator();

	if (ImGui::BeginTabBar("##KernelMemoryTabs")) {
		if (ImGui::BeginTabItem("Big Pool")) {
			BuildBigPoolTable();
			ImGui::EndTabItem();
		}
		if (ImGui::BeginTabItem("Pool Tags")) {
			BuildPoolTagTable();
			ImGui::EndTabItem();
		}
		ImGui::EndTabBar();
	}
}

void KernelMemoryView::BuildToolBar() {
	ImGui::Separator();
	DrawFilterToolbar();
	ImGui::SameLine();
	DrawUpdateIntervalToolbar("##KernelMemoryInterval", false);
}

void KernelMemoryView::BuildSummary() {
	ULONG64 executableBytes = 0;
	ULONG64 nonPagedBytes = 0;
	for (const auto& row : _bigPool) {
		if (row.NonPaged)
			nonPagedBytes += row.SizeInBytes;
		if (row.Executable)
			executableBytes += row.SizeInBytes;
	}

	ImGui::Text("Big Pool Entries: %zu", _bigPool.size());
	ImGui::SameLine();
	ImGui::TextDisabled("|");
	ImGui::SameLine();
	ImGui::Text("Pool Tags: %zu", _poolTags.size());
	ImGui::SameLine();
	ImGui::TextDisabled("|");
	ImGui::SameLine();
	ImGui::Text("NonPaged Bytes: %s", FormatHelper::FormatWithCommas(nonPagedBytes).GetString());
	ImGui::SameLine();
	ImGui::TextDisabled("|");
	ImGui::SameLine();
	ImGui::Text("Large NonPaged Bytes: %s", FormatHelper::FormatWithCommas(executableBytes).GetString());
}

void KernelMemoryView::BuildBigPoolTable() {
	auto filter = GetFilterTextLower();
	if (ImGui::BeginTable("##BigPoolTable", 5,
		ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
		ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable)) {
		ImGui::TableSetupScrollFreeze(0, 1);
		ImGui::TableSetupColumn("Address");
		ImGui::TableSetupColumn("Size");
		ImGui::TableSetupColumn("Tag");
		ImGui::TableSetupColumn("Pool");
		ImGui::TableSetupColumn("Flags");
		ImGui::TableHeadersRow();

		for (const auto& row : _bigPool) {
			CString tag(row.Tag.c_str());
			tag.MakeLower();
			if (!filter.IsEmpty() && tag.Find(filter) < 0)
				continue;

			ImGui::TableNextRow();
			ImGui::TableSetColumnIndex(0);
			ImGui::Text("0x%llX", row.VirtualAddress);
			ImGui::TableSetColumnIndex(1);
			ImGui::Text("%s", FormatHelper::FormatWithCommas(row.SizeInBytes).GetString());
			ImGui::TableSetColumnIndex(2);
			ImGui::TextUnformatted(row.Tag.c_str());
			ImGui::TableSetColumnIndex(3);
			ImGui::TextUnformatted(row.NonPaged ? "NonPaged" : "Paged");
			ImGui::TableSetColumnIndex(4);
			ImGui::TextUnformatted(row.Executable ? "Large/NP" : "-");
		}
		ImGui::EndTable();
	}
}

void KernelMemoryView::BuildPoolTagTable() {
	auto filter = GetFilterTextLower();
	if (ImGui::BeginTable("##PoolTagTable", 7,
		ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
		ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable)) {
		ImGui::TableSetupScrollFreeze(0, 1);
		ImGui::TableSetupColumn("Tag");
		ImGui::TableSetupColumn("Paged Allocs");
		ImGui::TableSetupColumn("Paged Frees");
		ImGui::TableSetupColumn("Paged Used");
		ImGui::TableSetupColumn("NonPaged Allocs");
		ImGui::TableSetupColumn("NonPaged Frees");
		ImGui::TableSetupColumn("NonPaged Used");
		ImGui::TableHeadersRow();

		for (const auto& row : _poolTags) {
			CString tag(row.Tag.c_str());
			tag.MakeLower();
			if (!filter.IsEmpty() && tag.Find(filter) < 0)
				continue;

			ImGui::TableNextRow();
			ImGui::TableSetColumnIndex(0);
			ImGui::TextUnformatted(row.Tag.c_str());
			ImGui::TableSetColumnIndex(1);
			ImGui::Text("%lu", row.PagedAllocs);
			ImGui::TableSetColumnIndex(2);
			ImGui::Text("%lu", row.PagedFrees);
			ImGui::TableSetColumnIndex(3);
			ImGui::Text("%s", FormatHelper::FormatWithCommas(row.PagedUsed).GetString());
			ImGui::TableSetColumnIndex(4);
			ImGui::Text("%lu", row.NonPagedAllocs);
			ImGui::TableSetColumnIndex(5);
			ImGui::Text("%lu", row.NonPagedFrees);
			ImGui::TableSetColumnIndex(6);
			ImGui::Text("%s", FormatHelper::FormatWithCommas(row.NonPagedUsed).GetString());
		}
		ImGui::EndTable();
	}
}
