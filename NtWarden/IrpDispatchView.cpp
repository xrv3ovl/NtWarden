#include "pch.h"
#include "imgui.h"
#include "IrpDispatchView.h"
#include "DriverHelper.h"
#include "RemoteClient.h"
#include "LoggerView.h"

#include <algorithm>

static const char* IrpMjNames[] = {
	"IRP_MJ_CREATE", "IRP_MJ_CREATE_NAMED_PIPE", "IRP_MJ_CLOSE", "IRP_MJ_READ",
	"IRP_MJ_WRITE", "IRP_MJ_QUERY_INFORMATION", "IRP_MJ_SET_INFORMATION",
	"IRP_MJ_QUERY_EA", "IRP_MJ_SET_EA", "IRP_MJ_FLUSH_BUFFERS",
	"IRP_MJ_QUERY_VOLUME_INFORMATION", "IRP_MJ_SET_VOLUME_INFORMATION",
	"IRP_MJ_DIRECTORY_CONTROL", "IRP_MJ_FILE_SYSTEM_CONTROL",
	"IRP_MJ_DEVICE_CONTROL", "IRP_MJ_INTERNAL_DEVICE_CONTROL",
	"IRP_MJ_SHUTDOWN", "IRP_MJ_LOCK_CONTROL", "IRP_MJ_CLEANUP",
	"IRP_MJ_CREATE_MAILSLOT", "IRP_MJ_QUERY_SECURITY", "IRP_MJ_SET_SECURITY",
	"IRP_MJ_POWER", "IRP_MJ_SYSTEM_CONTROL", "IRP_MJ_DEVICE_CHANGE",
	"IRP_MJ_QUERY_QUOTA", "IRP_MJ_SET_QUOTA", "IRP_MJ_PNP"
};

void IrpDispatchView::QueryDriver(const wchar_t* driverName) {
	if (_loading)
		return;
	_loading = true;
	std::wstring driverCopy(driverName ? driverName : L"");
	char selected[256]{};
	::WideCharToMultiByte(CP_ACP, 0, driverCopy.c_str(), -1, selected, sizeof(selected), nullptr, nullptr);
	_selectedDriverDisplay = selected;
	_queryFuture = std::async(std::launch::async, [driverCopy, selected]() -> std::vector<IrpEntry> {
		std::vector<IrpEntry> entries;

		IRP_DISPATCH_RESULT result{};
		bool ok;
		if (RemoteClient::IsConnected()) {
			ok = RemoteClient::GetIrpDispatch(selected, result);
		}
		else {
			ok = DriverHelper::GetIrpDispatch(driverCopy.c_str(), result);
		}
		if (!ok) {
			LoggerView::AddLog(LoggerView::UserModeLog, "IRP Dispatch: failed to query driver");
			return entries;
		}

		unsigned long moduleCount = 0;
		bool remote = RemoteClient::IsConnected();
		bool snapshotOk = remote ? RemoteClient::CreateModuleSnapshot(moduleCount) : DriverHelper::CreateModuleSnapshot(moduleCount);

		std::vector<KERNEL_MODULE_ENTRY> modules;
		if (snapshotOk) {
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
		}

		auto entryCount = (std::min)((unsigned long)IRP_MJ_MAXIMUM_FUNCTION_COUNT, result.Count);
		for (unsigned long i = 0; i < entryCount; i++) {
			IrpEntry entry{};
			entry.Index = static_cast<int>(i);
			entry.FunctionName = (i < _countof(IrpMjNames)) ? IrpMjNames[i] : "IRP_MJ_UNKNOWN";
			entry.Address = result.Entries[i].HandlerAddress;

			const KERNEL_MODULE_ENTRY* ownerMod = nullptr;
			for (const auto& mod : modules) {
				auto modStart = mod.ImageBase;
				auto modEnd = mod.ImageBase + mod.ImageSize;
				if (entry.Address >= modStart && entry.Address < modEnd) {
					ownerMod = &mod;
					break;
				}
			}

			entry.Owner = ownerMod ? ownerMod->Name : "<unknown>";
			entries.push_back(std::move(entry));
		}

		LoggerView::AddLog(LoggerView::UserModeLog, "IRP Dispatch: analyzed %zu entries for %s",
			entries.size(), selected);
		return entries;
	});
}

void IrpDispatchView::BuildWindow() {
	if (_loading && _queryFuture.valid() &&
		_queryFuture.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
		_entries = _queryFuture.get();
		_queried = true;
		_loading = false;
	}

	ImGui::InputText("Driver Object", _driverNameBuf, sizeof(_driverNameBuf));
	ImGui::SameLine();
	if (ImGui::Button("Query")) {
		wchar_t wide[256]{};
		::MultiByteToWideChar(CP_ACP, 0, _driverNameBuf, -1, wide, _countof(wide));
		QueryDriver(wide);
	}

	if (_loading) {
		ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "Querying IRP dispatch table...");
		return;
	}

	if (!_queried) {
		ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "Enter a driver object name and click Query.");
		return;
	}

	ImGui::Text("Entries: %zu", _entries.size());
	ImGui::Separator();

	if (ImGui::BeginTable("##IrpDispatch", 4,
		ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable |
		ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit, ImVec2(0, ImGui::GetTextLineHeightWithSpacing() * 24))) {
		ImGui::TableSetupScrollFreeze(0, 1);
		ImGui::TableSetupColumn("Index", 0, 50);
		ImGui::TableSetupColumn("IRP Function", 0, 260);
		ImGui::TableSetupColumn("Handler Address", 0, 140);
		ImGui::TableSetupColumn("Owner Module", ImGuiTableColumnFlags_WidthStretch);
		ImGui::TableHeadersRow();

		ImGuiListClipper clipper;
		clipper.Begin(static_cast<int>(_entries.size()));
		while (clipper.Step()) {
			for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
				const auto& item = _entries[i];
				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0);
				ImGui::Text("%d", item.Index);
				ImGui::TableSetColumnIndex(1);
				ImGui::TextUnformatted(item.FunctionName.c_str());
				ImGui::TableSetColumnIndex(2);
				ImGui::Text("0x%llX", item.Address);
				ImGui::TableSetColumnIndex(3);
				ImGui::TextUnformatted(item.Owner.c_str());
			}
		}
		ImGui::EndTable();
	}
}

void IrpDispatchView::RefreshNow() {
	wchar_t wide[256]{};
	::MultiByteToWideChar(CP_ACP, 0, _driverNameBuf, -1, wide, _countof(wide));
	QueryDriver(wide);
}
