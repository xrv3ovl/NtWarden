#include "pch.h"
#include "imgui.h"
#include "ServicesView.h"
#include <algorithm>
#include "SortHelper.h"
#include "TabManager.h"
#include <shellapi.h>
#include "FormatHelper.h"
#include "ImGuiExt.h"
#include "Globals.h"
#include "colors.h"
#include <WICTextureLoader.h>
#include <wincodec.h>
#include "resource.h"
#include "LoggerView.h"
#include "RemoteClient.h"


using namespace ImGui;

ServicesView::ServicesView() : ViewBase(1000) { }

namespace {
	std::wstring Utf8ToWide(const char* utf8) {
		if (!utf8 || !utf8[0]) return {};
		int size = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, nullptr, 0);
		std::wstring result(size - 1, 0);
		MultiByteToWideChar(CP_UTF8, 0, utf8, -1, result.data(), size);
		return result;
	}
}

void ServicesView::RefreshNow() {
	if (RemoteClient::IsConnected()) {
		// Launch async fetch if not already pending
		if (!_remoteFetchPending) {
			_remoteFuture = std::async(std::launch::async, []() {
				return RemoteClient::GetServices();
			});
			_remoteFetchPending = true;
		}
		// Check if async result is ready (non-blocking)
		if (_remoteFetchPending && _remoteFuture.valid() &&
			_remoteFuture.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
			auto netSvcs = _remoteFuture.get();
			_remoteFetchPending = false;
			_services.clear();
			_remoteBinaryPaths.clear();
			_services.reserve(netSvcs.size());
			for (auto& ns : netSvcs) {
				auto si = std::make_shared<WinSys::ServiceInfo>();
				si->_name = Utf8ToWide(ns.Name);
				si->_displayName = Utf8ToWide(ns.DisplayName);
				si->_status.ProcessId = ns.ProcessId;
				si->_status.Type = (WinSys::ServiceType)ns.Type;
				si->_status.CurrentState = (WinSys::ServiceState)ns.CurrentState;
				si->_status.ControlsAccepted = (WinSys::ServiceControlsAccepted)ns.ControlsAccepted;
				if (ns.BinaryPath[0])
					_remoteBinaryPaths[si->_name] = Utf8ToWide(ns.BinaryPath);
				_services.push_back(si);
			}
			if (_specs)
				DoSort(_specs->ColumnIndex, _specs->SortDirection == ImGuiSortDirection_Ascending);
			LoggerView::AddLog(LoggerView::UserModeLog, "Enumerated %zu services (remote)", _services.size());
			MarkUpdated();
		}
		return;
	}
	_services = _sm.EnumServices();
	_binaryPaths.clear();
	for (auto& s : _services) {
		auto config = WinSys::ServiceManager::GetServiceConfiguration(s->GetName());
		if (config)
			_binaryPaths[s->GetName()] = config->BinaryPathName;
	}
	if (_specs)
		DoSort(_specs->ColumnIndex, _specs->SortDirection == ImGuiSortDirection_Ascending);
	LoggerView::AddLog(LoggerView::UserModeLog, "Enumerated %zu services", _services.size());
	MarkUpdated();
}

const std::wstring& ServicesView::GetBinaryPath(const std::wstring& serviceName) {
	static const std::wstring empty;
	if (RemoteClient::IsConnected()) {
		auto it = _remoteBinaryPaths.find(serviceName);
		return it != _remoteBinaryPaths.end() ? it->second : empty;
	}
	auto it = _binaryPaths.find(serviceName);
	return it != _binaryPaths.end() ? it->second : empty;
}

void ServicesView::BuildToolBar() {
	Separator();
	DrawFilterToolbar();

	SameLine();
	DrawUpdateIntervalToolbar("##ServiceUpdateInterval", false);
}

PCWSTR ServicesView::ServiceStateToString(WinSys::ServiceState state) {
	using enum WinSys::ServiceState;
	switch (state) {
	case Running: return L"Running";
	case Stopped: return L"Stopped";
	case Paused: return L"Paused";
	case StartPending: return L"Start Pending";
	case ContinuePending: return L"Continue Pending";
	case StopPending: return L"Stop Pending";
	case PausePending: return L"Pause Pending";
	}
	return L"Unknown";
}

void ServicesView::DoSort(int col, bool asc) {
	std::sort(_services.begin(), _services.end(), [=](const auto& s1, const auto& s2) {
		switch (col) {
		case 0: return SortHelper::SortStrings(s1->GetName(), s2->GetName(), asc);
		case 1: return SortHelper::SortStrings(s1->GetDisplayName(), s2->GetDisplayName(), asc);
		case 2: return SortHelper::SortStrings(ServiceStateToString(s1->GetStatusProcess().CurrentState),
			ServiceStateToString(s2->GetStatusProcess().CurrentState),
			asc);
		case 3: return SortHelper::SortStrings(GetBinaryPath(s1->GetName()), GetBinaryPath(s2->GetName()), asc);
		}
	return false;
		});
}


void ServicesView::BuildTable() {
	bool remote = RemoteClient::IsConnected();

	if (BeginTable("svcTable", 4, ImGuiTableFlags_BordersV * 0 | ImGuiTableFlags_Sortable |
		ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable | 0 * ImGuiTableFlags_NoSavedSettings | ImGuiTableFlags_ScrollX | ImGuiTableFlags_ScrollY |
		ImGuiTableFlags_RowBg | ImGuiTableFlags_Hideable | ImGuiTableFlags_NoSavedSettings
	)) {
		TableSetupScrollFreeze(1, 1);
		TableSetupColumn("Name", ImGuiTableColumnFlags_NoHide | ImGuiTableColumnFlags_NoReorder);
		TableSetupColumn("Display Name");
		TableSetupColumn("Current State");
		TableSetupColumn("Executable Path");

		TableHeadersRow();

		if (IsUpdateDue()) {
			RefreshNow();
		}

		auto filter = GetFilterTextLower();
		std::vector<int> indices;
		indices.reserve(_services.size());

		auto count = static_cast<int>(_services.size());
		for (int i = 0; i < count; i++) {
			auto& s = _services[i];
			s->Filtered = false;
			if (!filter.IsEmpty()) {
				CString name(s->GetName().c_str());
				name.MakeLower();
				if (name.Find(filter) < 0) {
					s->Filtered = true;
					continue;
				}
			}
			indices.push_back(i);
		}

		auto specs = TableGetSortSpecs();
		if (specs && specs->SpecsDirty) {
			_specs = specs->Specs;
			DoSort(_specs->ColumnIndex, _specs->SortDirection == ImGuiSortDirection_Ascending);
			specs->SpecsDirty = false;
		}

		USES_CONVERSION;
		ImGuiListClipper clipper;

		count = static_cast<int>(indices.size());
		clipper.Begin(count);

		static bool selected = false;
		CStringA str;
		static char buffer[64];
		int popCount = 3;
		auto special = false;

		while (clipper.Step()) {
			for (int j = clipper.DisplayStart; j < clipper.DisplayEnd; j++) {
				int i = indices[j];
				auto& s = _services[i];
				if (s->Filtered) {
					clipper.ItemsCount--;
					continue;
				}
				TableNextRow();

				if (special)
					PopStyleColor(popCount);
				if (_selectedService != nullptr)
				{
					special = s->_name == _selectedService->_name;
					if (special)
					{
						const auto& color = GetStyle().Colors[ImGuiCol_TextSelectedBg];
						PushStyleColor(ImGuiCol_TableRowBg, color);
						PushStyleColor(ImGuiCol_TableRowBgAlt, color);
						PushStyleColor(ImGuiCol_Text, GetStyle().Colors[ImGuiCol_Text]);
					}
				}

				WinSys::ServiceState svc_state = s->GetStatusProcess().CurrentState;
				if (svc_state == WinSys::ServiceState::Stopped)
					ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.5019608f, 0.5019608f, 0.5019608f, 1));

				TableSetColumnIndex(0);
				str.Format("%ws##%d", s->GetName().c_str(), i);
				Selectable(str, false, ImGuiSelectableFlags_SpanAllColumns);

				::StringCchPrintfA(buffer, sizeof(buffer), "##%d", i);

				if (IsItemClicked()) {
					LoggerView::AddLog(LoggerView::UserModeLog, str);
					_selectedService = s;
				}
				if (IsItemClicked(ImGuiMouseButton_Right))
					_selectedService = s;

				// Right-click context menu (local only)
				if (!remote && BeginPopupContextItem()) {
					auto accepted = s->GetStatusProcess().ControlsAccepted;
					bool canStop = (int)(accepted & WinSys::ServiceControlsAccepted::Stop) != 0;
					bool canPause = (int)(accepted & WinSys::ServiceControlsAccepted::PauseContinue) != 0;
					bool isStopped = svc_state == WinSys::ServiceState::Stopped;
					bool isRunning = svc_state == WinSys::ServiceState::Running;
					bool isPaused = svc_state == WinSys::ServiceState::Paused;

					if (MenuItem("Start", nullptr, false, isStopped)) {
						auto svc = WinSys::Service::Open(s->GetName(),
							WinSys::ServiceAccessMask::Start);
						if (svc && svc->Start())
							LoggerView::AddLog(LoggerView::UserModeLog, "Started service: %ws", s->GetName().c_str());
						else
							LoggerView::AddLog(LoggerView::UserModeLog, "Failed to start service: %ws", s->GetName().c_str());
					}
					if (MenuItem("Stop", nullptr, false, canStop && (isRunning || isPaused))) {
						auto svc = WinSys::Service::Open(s->GetName(),
							WinSys::ServiceAccessMask::Stop);
						if (svc && svc->Stop())
							LoggerView::AddLog(LoggerView::UserModeLog, "Stopped service: %ws", s->GetName().c_str());
						else
							LoggerView::AddLog(LoggerView::UserModeLog, "Failed to stop service: %ws", s->GetName().c_str());
					}
					if (MenuItem("Pause", nullptr, false, canPause && isRunning)) {
						auto svc = WinSys::Service::Open(s->GetName(),
							WinSys::ServiceAccessMask::PauseContinue);
						if (svc && svc->Pause())
							LoggerView::AddLog(LoggerView::UserModeLog, "Paused service: %ws", s->GetName().c_str());
						else
							LoggerView::AddLog(LoggerView::UserModeLog, "Failed to pause service: %ws", s->GetName().c_str());
					}
					if (MenuItem("Resume", nullptr, false, canPause && isPaused)) {
						auto svc = WinSys::Service::Open(s->GetName(),
							WinSys::ServiceAccessMask::PauseContinue);
						if (svc && svc->Continue())
							LoggerView::AddLog(LoggerView::UserModeLog, "Resumed service: %ws", s->GetName().c_str());
						else
							LoggerView::AddLog(LoggerView::UserModeLog, "Failed to resume service: %ws", s->GetName().c_str());
					}
					if (MenuItem("Restart", nullptr, false, canStop && isRunning)) {
						auto svc = WinSys::Service::Open(s->GetName(),
							WinSys::ServiceAccessMask::Start | WinSys::ServiceAccessMask::Stop | WinSys::ServiceAccessMask::QueryStatus);
						if (svc) {
							svc->Stop();
							// Wait briefly for the service to stop before restarting
							for (int w = 0; w < 20; w++) {
								::Sleep(100);
								auto status = svc->GetStatus();
								if (status.CurrentState == WinSys::ServiceState::Stopped)
									break;
							}
							if (svc->Start())
								LoggerView::AddLog(LoggerView::UserModeLog, "Restarted service: %ws", s->GetName().c_str());
							else
								LoggerView::AddLog(LoggerView::UserModeLog, "Failed to restart service: %ws", s->GetName().c_str());
						}
						else {
							LoggerView::AddLog(LoggerView::UserModeLog, "Failed to open service for restart: %ws", s->GetName().c_str());
						}
					}

					Separator();
					if (BeginMenu("Copy")) {
						if (MenuItem("Service Name")) {
							char buf[256];
							sprintf_s(buf, "%ws", s->GetName().c_str());
							SetClipboardText(buf);
						}
						if (MenuItem("Display Name")) {
							char buf[256];
							sprintf_s(buf, "%ws", s->GetDisplayName().c_str());
							SetClipboardText(buf);
						}
						if (MenuItem("Executable Path")) {
							auto& path = GetBinaryPath(s->GetName());
							char buf[520];
							sprintf_s(buf, "%ws", path.c_str());
							SetClipboardText(buf);
						}
						ImGui::EndMenu();
					}

					EndPopup();
				}

				if (TableSetColumnIndex(1)) {
					Text("%ws", s->GetDisplayName().c_str());
				}

				if (TableSetColumnIndex(2)) {
					Text("%ws", ServiceStateToString(svc_state));
				}

				if (TableSetColumnIndex(3)) {
					Text("%ws", GetBinaryPath(s->GetName()).c_str());
				}

				if (svc_state == WinSys::ServiceState::Stopped)
					ImGui::PopStyleColor();

			}
		}
		if (special) {
			PopStyleColor(popCount);
		}

		ImGui::EndTable();
	}
}

void ServicesView::BuildWindow() {
	BuildToolBar();
	BuildTable();
}


