#include "pch.h"
#include "MiniFilterView.h"
#include "ImGuiExt.h"
#include "RemoteClient.h"
#include "LoggerView.h"
#include "Utils.h"
#include <fltUser.h>

#pragma comment(lib, "FltLib.lib")

ImGuiTableFlags MiniFilterView::table_flags =
	ImGuiTableFlags_ScrollX |
	ImGuiTableFlags_ScrollY |
	ImGuiTableFlags_BordersV |
	ImGuiTableFlags_BordersOuterH |
	ImGuiTableFlags_RowBg |
	ImGuiTableFlags_Sortable |
	ImGuiTableFlags_ContextMenuInBody |
	ImGuiTableFlags_SortTristate |
	ImGuiTableFlags_Resizable;

void MiniFilterView::Refresh() {
	_filters.clear();
	_instances.clear();
	_selectedFilter = -1;
	_selectedFilterName.clear();

	if (RemoteClient::IsConnected()) {
		auto remote = RemoteClient::GetMiniFilters();
		for (const auto& m : remote) {
			MiniFilterEntry entry{};
			int chars;
			chars = ::MultiByteToWideChar(CP_UTF8, 0, m.Name, -1, nullptr, 0);
			entry.FilterName.resize(chars > 0 ? chars - 1 : 0);
			if (chars > 0) ::MultiByteToWideChar(CP_UTF8, 0, m.Name, -1, entry.FilterName.data(), chars);
			chars = ::MultiByteToWideChar(CP_UTF8, 0, m.Altitude, -1, nullptr, 0);
			entry.Altitude.resize(chars > 0 ? chars - 1 : 0);
			if (chars > 0) ::MultiByteToWideChar(CP_UTF8, 0, m.Altitude, -1, entry.Altitude.data(), chars);
			entry.NumberOfInstances = m.Instances;
			entry.FrameID = m.FrameId;
			_filters.push_back(std::move(entry));
		}
	LoggerView::AddLog(LoggerView::UserModeLog, "Enumerated %zu minifilter drivers (remote)", _filters.size());
		return;
	}

	HANDLE hFind = INVALID_HANDLE_VALUE;
	BYTE buffer[4096];
	PFILTER_AGGREGATE_STANDARD_INFORMATION info;
	DWORD bytesReturned = 0;

	HRESULT hr = FilterFindFirst(
		FilterAggregateStandardInformation,
		buffer,
		sizeof(buffer),
		&bytesReturned,
		&hFind);

	while (SUCCEEDED(hr)) {
		info = (PFILTER_AGGREGATE_STANDARD_INFORMATION)buffer;

		while ((PBYTE)info < buffer + bytesReturned) {
			MiniFilterEntry entry{};

			if (info->Flags == FLTFL_ASI_IS_MINIFILTER) {
				auto& mf = info->Type.MiniFilter;

				if (mf.FilterNameLength > 0) {
					entry.FilterName.assign(
						(PCWSTR)((PBYTE)info + mf.FilterNameBufferOffset),
						mf.FilterNameLength / sizeof(WCHAR));
				}
				if (mf.FilterAltitudeLength > 0) {
					entry.Altitude.assign(
						(PCWSTR)((PBYTE)info + mf.FilterAltitudeBufferOffset),
						mf.FilterAltitudeLength / sizeof(WCHAR));
				}
				entry.FrameID = mf.FrameID;
				entry.NumberOfInstances = mf.NumberOfInstances;
				_filters.push_back(std::move(entry));
			}
			else if (info->Flags == FLTFL_ASI_IS_LEGACYFILTER) {
				auto& lf = info->Type.LegacyFilter;

				if (lf.FilterNameLength > 0) {
					entry.FilterName.assign(
						(PCWSTR)((PBYTE)info + lf.FilterNameBufferOffset),
						lf.FilterNameLength / sizeof(WCHAR));
				}
				if (lf.FilterAltitudeLength > 0) {
					entry.Altitude.assign(
						(PCWSTR)((PBYTE)info + lf.FilterAltitudeBufferOffset),
						lf.FilterAltitudeLength / sizeof(WCHAR));
				}
				entry.FrameID = 0;
				entry.NumberOfInstances = 0;
				_filters.push_back(std::move(entry));
			}

			if (info->NextEntryOffset == 0)
				break;
			info = (PFILTER_AGGREGATE_STANDARD_INFORMATION)((PBYTE)info + info->NextEntryOffset);
		}

		hr = FilterFindNext(
			hFind,
			FilterAggregateStandardInformation,
			buffer,
			sizeof(buffer),
			&bytesReturned);
	}

	if (hFind != INVALID_HANDLE_VALUE)
		FilterFindClose(hFind);

	LoggerView::AddLog(LoggerView::UserModeLog, "Enumerated %zu minifilter drivers", _filters.size());
}

static void EnumFilterInstances(const std::wstring& filterName, std::vector<MiniFilterInstanceEntry>& instances) {
	instances.clear();

	if (RemoteClient::IsConnected()) {
		auto narrow = Utils::WideToUtf8(filterName.c_str());
		auto remote = RemoteClient::GetFilterInstances(narrow);
		for (const auto& fi : remote) {
			MiniFilterInstanceEntry inst{};
			int chars;
			chars = ::MultiByteToWideChar(CP_UTF8, 0, fi.InstanceName, -1, nullptr, 0);
			inst.InstanceName.resize(chars > 0 ? chars - 1 : 0);
			if (chars > 0) ::MultiByteToWideChar(CP_UTF8, 0, fi.InstanceName, -1, inst.InstanceName.data(), chars);
			chars = ::MultiByteToWideChar(CP_UTF8, 0, fi.VolumeName, -1, nullptr, 0);
			inst.VolumeName.resize(chars > 0 ? chars - 1 : 0);
			if (chars > 0) ::MultiByteToWideChar(CP_UTF8, 0, fi.VolumeName, -1, inst.VolumeName.data(), chars);
			instances.push_back(std::move(inst));
		}
		return;
	}

	HANDLE hFind = INVALID_HANDLE_VALUE;
	BYTE buffer[4096];
	DWORD bytesReturned = 0;

	HRESULT hr = FilterInstanceFindFirst(
		filterName.c_str(),
		InstanceFullInformation,
		buffer,
		sizeof(buffer),
		&bytesReturned,
		&hFind);

	while (SUCCEEDED(hr)) {
		auto info = (PINSTANCE_FULL_INFORMATION)buffer;

		while ((PBYTE)info < buffer + bytesReturned) {
			MiniFilterInstanceEntry inst{};

			if (info->InstanceNameLength > 0) {
				inst.InstanceName.assign(
					(PCWSTR)((PBYTE)info + info->InstanceNameBufferOffset),
					info->InstanceNameLength / sizeof(WCHAR));
			}
			if (info->VolumeNameLength > 0) {
				inst.VolumeName.assign(
					(PCWSTR)((PBYTE)info + info->VolumeNameBufferOffset),
					info->VolumeNameLength / sizeof(WCHAR));
			}

			instances.push_back(std::move(inst));

			if (info->NextEntryOffset == 0)
				break;
			info = (PINSTANCE_FULL_INFORMATION)((PBYTE)info + info->NextEntryOffset);
		}

		hr = FilterInstanceFindNext(
			hFind,
			InstanceFullInformation,
			buffer,
			sizeof(buffer),
			&bytesReturned);
	}

	if (hFind != INVALID_HANDLE_VALUE)
		FilterInstanceFindClose(hFind);
}

void MiniFilterView::BuildWindow() {
	if (_needsRefresh) {
		Refresh();
		_needsRefresh = false;
	}

	ImGui::Text("MiniFilter Drivers (%d)", (int)_filters.size());

	const float TEXT_BASE_HEIGHT = ImGui::GetTextLineHeightWithSpacing();

	float filterTableHeight = TEXT_BASE_HEIGHT * 14;
	if (ImGui::BeginTable("MiniFiltersTable", 4, table_flags, ImVec2(0.0f, filterTableHeight))) {
		ImGui::TableSetupScrollFreeze(0, 1);
		ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
		ImGui::TableSetupColumn("Altitude", ImGuiTableColumnFlags_WidthFixed, 100.0f);
		ImGui::TableSetupColumn("Instances", ImGuiTableColumnFlags_WidthFixed, 80.0f);
		ImGui::TableSetupColumn("Frame", ImGuiTableColumnFlags_WidthFixed, 60.0f);
		ImGui::TableHeadersRow();

		ImGuiListClipper clipper;
		clipper.Begin((int)_filters.size());
		while (clipper.Step()) {
			for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; row++) {
				auto& f = _filters[row];
				auto name = Utils::WideToUtf8(f.FilterName.c_str());
				auto alt = Utils::WideToUtf8(f.Altitude.c_str());

				ImGui::PushID(row);
				ImGui::TableNextRow();

				ImGui::TableNextColumn();
				bool selected = (_selectedFilter == row);
				if (ImGui::Selectable(name.c_str(), selected,
					ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowItemOverlap)) {
					_selectedFilter = row;
					_selectedFilterName = f.FilterName;
					EnumFilterInstances(_selectedFilterName, _instances);
				}

				ImGui::TableNextColumn();
				ImGui::Text("%s", alt.c_str());

				ImGui::TableNextColumn();
				ImGui::Text("%lu", f.NumberOfInstances);

				ImGui::TableNextColumn();
				ImGui::Text("%lu", f.FrameID);

				ImGui::PopID();
			}
		}
		ImGui::EndTable();
	}

	ImGui::Separator();

	if (_selectedFilter >= 0 && _selectedFilter < (int)_filters.size()) {
		auto selName = Utils::WideToUtf8(_filters[_selectedFilter].FilterName.c_str());
		ImGui::Text("Instances for: %s (%d)", selName.c_str(), (int)_instances.size());

		if (ImGui::BeginTable("FilterInstancesTable", 2, table_flags, ImVec2(0.0f, TEXT_BASE_HEIGHT * 8))) {
			ImGui::TableSetupScrollFreeze(0, 1);
			ImGui::TableSetupColumn("Instance Name", ImGuiTableColumnFlags_WidthStretch);
			ImGui::TableSetupColumn("Volume", ImGuiTableColumnFlags_WidthStretch);
			ImGui::TableHeadersRow();

			for (int i = 0; i < (int)_instances.size(); i++) {
				auto& inst = _instances[i];
				ImGui::TableNextRow();

				ImGui::TableNextColumn();
				auto instName = Utils::WideToUtf8(inst.InstanceName.c_str());
				ImGui::Text("%s", instName.c_str());

				ImGui::TableNextColumn();
				auto volName = Utils::WideToUtf8(inst.VolumeName.c_str());
				ImGui::Text("%s", volName.c_str());
			}
			ImGui::EndTable();
		}
	}
	else {
		ImGui::TextDisabled("Select a filter above to see its instances");
	}
}
