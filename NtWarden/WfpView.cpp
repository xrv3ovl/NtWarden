#include "pch.h"
#include "imgui.h"
#include "WfpView.h"
#include "DriverHelper.h"
#include "RemoteClient.h"
#include "LoggerView.h"
#include "Utils.h"

static ImGuiTableFlags table_flags =
	ImGuiTableFlags_ScrollX |
	ImGuiTableFlags_ScrollY |
	ImGuiTableFlags_BordersV |
	ImGuiTableFlags_BordersOuterH |
	ImGuiTableFlags_RowBg |
	ImGuiTableFlags_Resizable;

static const char* ActionTypeToString(unsigned long action) {
	switch (action) {
	case 0x1001: return "FWP_ACTION_PERMIT";
	case 0x1002: return "FWP_ACTION_CONTINUE";
	case 0x2001: return "FWP_ACTION_BLOCK";
	case 0x4003: return "FWP_ACTION_CALLOUT_TERMINATING";
	case 0x5003: return "FWP_ACTION_CALLOUT_INSPECTION";
	case 0x6003: return "FWP_ACTION_CALLOUT_UNKNOWN";
	default:     return "Unknown";
	}
}

void WfpView::RefreshFilters() {
	if (_filtersLoading) return;
	_filtersLoading = true;
	_filtersFuture = std::async(std::launch::async, []() -> std::vector<WFP_FILTER_ENTRY> {
		std::vector<WFP_FILTER_ENTRY> filters;
		if (RemoteClient::IsConnected())
			filters = RemoteClient::GetWfpFilters();
		else
			DriverHelper::EnumWfpFilters(filters);
	LoggerView::AddLog(LoggerView::UserModeLog, "Enumerated %zu WFP filters", filters.size());
		return filters;
	});
}

void WfpView::RefreshCallouts() {
	if (_calloutsLoading) return;
	_calloutsLoading = true;
	_calloutsFuture = std::async(std::launch::async, []() -> std::vector<WFP_CALLOUT_ENTRY> {
		std::vector<WFP_CALLOUT_ENTRY> callouts;
		if (RemoteClient::IsConnected())
			callouts = RemoteClient::GetWfpCallouts();
		else
			DriverHelper::EnumWfpCallouts(callouts);
	LoggerView::AddLog(LoggerView::UserModeLog, "Enumerated %zu WFP callouts", callouts.size());
		return callouts;
	});
}

void WfpView::RefreshNow() {
	RefreshFilters();
	RefreshCallouts();
}

void WfpView::BuildWindow() {
	if (_filtersLoading && _filtersFuture.valid() &&
		_filtersFuture.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
		_filters = _filtersFuture.get();
		_filtersLoaded = true;
		_filtersLoading = false;
	}
	if (_calloutsLoading && _calloutsFuture.valid() &&
		_calloutsFuture.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
		_callouts = _calloutsFuture.get();
		_calloutsLoaded = true;
		_calloutsLoading = false;
	}

	if (ImGui::BeginTabBar("##WfpTabs")) {
		if (ImGui::BeginTabItem("Filters")) {
			BuildFiltersTab();
			ImGui::EndTabItem();
		}
		if (ImGui::BeginTabItem("Callouts")) {
			BuildCalloutsTab();
			ImGui::EndTabItem();
		}
		ImGui::EndTabBar();
	}
}

void WfpView::BuildFiltersTab() {
	if (!_filtersLoaded)
		RefreshFilters();
	if (_filtersLoading) {
		ImGui::TextUnformatted("Enumerating WFP filters...");
		return;
	}

	ImGui::Text("Filters: %zu", _filters.size());

	const float TEXT_BASE_HEIGHT = ImGui::GetTextLineHeightWithSpacing();

	if (ImGui::BeginTable("WfpFiltersTable", 6, table_flags, ImVec2(0.0f, TEXT_BASE_HEIGHT * 20))) {
		ImGui::TableSetupScrollFreeze(0, 1);
		ImGui::TableSetupColumn("Filter ID", ImGuiTableColumnFlags_WidthFixed, 100.0f);
		ImGui::TableSetupColumn("Display Name", ImGuiTableColumnFlags_WidthStretch);
		ImGui::TableSetupColumn("Layer", ImGuiTableColumnFlags_WidthStretch);
		ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthFixed, 220.0f);
		ImGui::TableSetupColumn("Flags", ImGuiTableColumnFlags_WidthFixed, 80.0f);
		ImGui::TableSetupColumn("Provider", ImGuiTableColumnFlags_WidthStretch);
		ImGui::TableHeadersRow();

		ImGuiListClipper clipper;
		clipper.Begin((int)_filters.size());
		while (clipper.Step()) {
			for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; row++) {
				auto& f = _filters[row];

				ImGui::PushID(row);
				ImGui::TableNextRow();

				ImGui::TableNextColumn();
				ImGui::Text("%llu", f.FilterId);

				ImGui::TableNextColumn();
				ImGui::TextUnformatted(Utils::WideToUtf8(f.DisplayName).c_str());

				ImGui::TableNextColumn();
				ImGui::TextUnformatted(f.LayerName);

				ImGui::TableNextColumn();
				const char* actionStr = ActionTypeToString(f.ActionType);
				if (f.ActionType == 0x2001) {
					ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "%s", actionStr);
				}
				else if (f.ActionType == 0x1001) {
					ImGui::TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), "%s", actionStr);
				}
				else {
					ImGui::Text("%s", actionStr);
				}

				ImGui::TableNextColumn();
				ImGui::Text("0x%X", f.Flags);

				ImGui::TableNextColumn();
				ImGui::TextUnformatted(f.ProviderName);

				ImGui::PopID();
			}
		}
		ImGui::EndTable();
	}
}

void WfpView::BuildCalloutsTab() {
	if (!_calloutsLoaded)
		RefreshCallouts();
	if (_calloutsLoading) {
		ImGui::TextUnformatted("Enumerating WFP callouts...");
		return;
	}

	ImGui::Text("Callouts: %zu", _callouts.size());

	const float TEXT_BASE_HEIGHT = ImGui::GetTextLineHeightWithSpacing();

	if (ImGui::BeginTable("WfpCalloutsTable", 8, table_flags, ImVec2(0.0f, TEXT_BASE_HEIGHT * 20))) {
		ImGui::TableSetupScrollFreeze(0, 1);
		ImGui::TableSetupColumn("Callout ID", ImGuiTableColumnFlags_WidthFixed, 100.0f);
		ImGui::TableSetupColumn("Display Name", ImGuiTableColumnFlags_WidthStretch);
		ImGui::TableSetupColumn("Layer", ImGuiTableColumnFlags_WidthStretch);
		ImGui::TableSetupColumn("Classify Fn", ImGuiTableColumnFlags_WidthFixed, 160.0f);
		ImGui::TableSetupColumn("Notify Fn", ImGuiTableColumnFlags_WidthFixed, 160.0f);
		ImGui::TableSetupColumn("Flow Delete Fn", ImGuiTableColumnFlags_WidthFixed, 160.0f);
		ImGui::TableSetupColumn("Flags", ImGuiTableColumnFlags_WidthFixed, 80.0f);
		ImGui::TableSetupColumn("Provider", ImGuiTableColumnFlags_WidthStretch);
		ImGui::TableHeadersRow();

		ImGuiListClipper clipper;
		clipper.Begin((int)_callouts.size());
		while (clipper.Step()) {
			for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; row++) {
				auto& c = _callouts[row];

				ImGui::PushID(row);
				ImGui::TableNextRow();

				ImGui::TableNextColumn();
				ImGui::Text("%lu", c.CalloutId);

				ImGui::TableNextColumn();
				ImGui::TextUnformatted(Utils::WideToUtf8(c.DisplayName).c_str());

				ImGui::TableNextColumn();
				ImGui::TextUnformatted(c.LayerName);

				ImGui::TableNextColumn();
				if (c.ClassifyFunction)
					ImGui::Text("0x%016llX", c.ClassifyFunction);
				else
					ImGui::TextUnformatted("-");

				ImGui::TableNextColumn();
				if (c.NotifyFunction)
					ImGui::Text("0x%016llX", c.NotifyFunction);
				else
					ImGui::TextUnformatted("-");

				ImGui::TableNextColumn();
				if (c.FlowDeleteFunction)
					ImGui::Text("0x%016llX", c.FlowDeleteFunction);
				else
					ImGui::TextUnformatted("-");

				ImGui::TableNextColumn();
				ImGui::Text("0x%X", c.Flags);

				ImGui::TableNextColumn();
				ImGui::TextUnformatted(c.ProviderName);

				ImGui::PopID();
			}
		}
		ImGui::EndTable();
	}
}
