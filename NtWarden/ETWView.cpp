#include "pch.h"
#include "imgui.h"
#include "ETWView.h"
#include "RemoteClient.h"
#include "LoggerView.h"
#include <evntrace.h>
#include <tdh.h>

#pragma comment(lib, "Tdh.lib")

using namespace ImGui;

namespace {
	std::wstring GuidToString(const GUID& guid) {
		WCHAR buffer[64]{};
		::StringFromGUID2(guid, buffer, _countof(buffer));
		return buffer;
	}

	std::wstring LoggerModeToString(ULONG mode) {
		CStringW text;
		text.Format(L"0x%08X", mode);
		return std::wstring(text);
	}

	std::string WideToUtf8(const std::wstring& ws) {
		if (ws.empty()) return {};
		int len = ::WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), nullptr, 0, nullptr, nullptr);
		std::string s(len, '\0');
		::WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), s.data(), len, nullptr, nullptr);
		return s;
	}

	std::string WideToUtf8(const wchar_t* ws) {
		if (!ws || !*ws) return {};
		return WideToUtf8(std::wstring(ws));
	}

}

ETWView::ETWView() : ViewBase(10000)
{
	Refresh();
}

void ETWView::RefreshNow() {
	Refresh();
	MarkUpdated();
}

void ETWView::BuildWindow()
{
	BuildToolBar();
	if (IsUpdateDue()) {
		Refresh();
		MarkUpdated();
	}

	if (ImGui::BeginTabBar("EtwTabBar")) {
		if (ImGui::BeginTabItem("Sessions")) {
			BuildSessionsTable();
			ImGui::EndTabItem();
		}
		if (ImGui::BeginTabItem("Providers")) {
			BuildProvidersTable();
			ImGui::EndTabItem();
		}
ImGui::EndTabBar();
	}
}

void ETWView::BuildToolBar()
{
	DrawFilterToolbar();

	SameLine();
	DrawUpdateIntervalToolbar("##EtwUpdateInterval", false);
}

void ETWView::Refresh() {
	_sessions.clear();
	_providers.clear();

	if (RemoteClient::IsConnected()) {
		auto remoteSessions = RemoteClient::GetEtwSessions();
		for (const auto& s : remoteSessions) {
			SessionInfo info;
			int chars = ::MultiByteToWideChar(CP_UTF8, 0, s.Name, -1, nullptr, 0);
			info.Name.resize(chars > 0 ? chars - 1 : 0);
			if (chars > 0)
				::MultiByteToWideChar(CP_UTF8, 0, s.Name, -1, info.Name.data(), chars);
			info.BufferSizeMb = s.BufferSize;
			info.BuffersWritten = s.BuffersWritten;
			info.EventsLost = s.EventsLost;
			info.LogFileMode = s.LogFileMode;
			_sessions.push_back(std::move(info));
		}

		auto remoteProviders = RemoteClient::GetEtwProviders();
		for (const auto& p : remoteProviders) {
			ProviderInfo info;
			int chars = ::MultiByteToWideChar(CP_UTF8, 0, p.Name, -1, nullptr, 0);
			info.Name.resize(chars > 0 ? chars - 1 : 0);
			if (chars > 0)
				::MultiByteToWideChar(CP_UTF8, 0, p.Name, -1, info.Name.data(), chars);
			chars = ::MultiByteToWideChar(CP_UTF8, 0, p.Guid, -1, nullptr, 0);
			info.Guid.resize(chars > 0 ? chars - 1 : 0);
			if (chars > 0)
				::MultiByteToWideChar(CP_UTF8, 0, p.Guid, -1, info.Guid.data(), chars);
			_providers.push_back(std::move(info));
		}

		LoggerView::AddLog(LoggerView::UserModeLog, "Enumerated %zu ETW sessions, %zu providers (remote)", _sessions.size(), _providers.size());
		return;
	}

	constexpr ULONG maxSessionCount = 64;
	std::vector<std::vector<BYTE>> sessionBuffers;
	std::vector<PEVENT_TRACE_PROPERTIES> properties;
	sessionBuffers.reserve(maxSessionCount);
	properties.reserve(maxSessionCount);

	for (ULONG i = 0; i < maxSessionCount; i++) {
		sessionBuffers.emplace_back(sizeof(EVENT_TRACE_PROPERTIES) + 2048, 0);
		auto prop = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(sessionBuffers.back().data());
		prop->Wnode.BufferSize = static_cast<ULONG>(sessionBuffers.back().size());
		prop->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
		prop->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + 1024;
		properties.push_back(prop);
	}

	ULONG sessionCount = maxSessionCount;
	auto status = ::QueryAllTraces(properties.data(), maxSessionCount, &sessionCount);
	if (status == ERROR_SUCCESS) {
		for (ULONG i = 0; i < sessionCount; i++) {
			const auto prop = properties[i];
			SessionInfo info;
			info.Name = reinterpret_cast<PCWSTR>(reinterpret_cast<const BYTE*>(prop) + prop->LoggerNameOffset);
			info.BufferSizeMb = prop->BufferSize;
			info.BuffersWritten = prop->BuffersWritten;
			info.EventsLost = prop->EventsLost;
			info.LogFileMode = prop->LogFileMode;
			_sessions.push_back(std::move(info));
		}
	}

	ULONG providerSize = 0;
	status = ::TdhEnumerateProviders(nullptr, &providerSize);
	if (status == ERROR_INSUFFICIENT_BUFFER && providerSize > 0) {
		std::vector<BYTE> providerBuffer(providerSize);
		auto providerInfo = reinterpret_cast<PPROVIDER_ENUMERATION_INFO>(providerBuffer.data());
		status = ::TdhEnumerateProviders(providerInfo, &providerSize);
		if (status == ERROR_SUCCESS) {
			for (ULONG i = 0; i < providerInfo->NumberOfProviders; i++) {
				const auto& provider = providerInfo->TraceProviderInfoArray[i];
				ProviderInfo info;
				info.Name = reinterpret_cast<PCWSTR>(providerBuffer.data() + provider.ProviderNameOffset);
				info.Guid = GuidToString(provider.ProviderGuid);
				_providers.push_back(std::move(info));
			}
		}
	}

	LoggerView::AddLog(LoggerView::UserModeLog, "Enumerated %zu ETW sessions, %zu providers", _sessions.size(), _providers.size());
}

void ETWView::BuildSessionsTable() {
	auto filter = GetFilterTextLower();
	if (BeginTable("etwSessionsTable", 5, ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable |
		ImGuiTableFlags_ScrollX | ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg |
		ImGuiTableFlags_Hideable | ImGuiTableFlags_NoSavedSettings)) {
		TableSetupScrollFreeze(1, 1);
		TableSetupColumn("Name");
		TableSetupColumn("Buffer Size (MB)");
		TableSetupColumn("Buffers Written");
		TableSetupColumn("Events Lost");
		TableSetupColumn("Mode");
		TableHeadersRow();

		for (const auto& session : _sessions) {
			if (!filter.IsEmpty()) {
				CString haystack((session.Name + L" " + LoggerModeToString(session.LogFileMode)).c_str());
				haystack.MakeLower();
				if (haystack.Find(filter) < 0)
					continue;
			}

			TableNextRow();
			TableSetColumnIndex(0);
			Text("%ws", session.Name.c_str());
			TableSetColumnIndex(1);
			Text("%u", session.BufferSizeMb);
			TableSetColumnIndex(2);
			Text("%u", session.BuffersWritten);
			TableSetColumnIndex(3);
			Text("%u", session.EventsLost);
			TableSetColumnIndex(4);
			Text("%ws", LoggerModeToString(session.LogFileMode).c_str());
		}

		EndTable();
	}
}

void ETWView::BuildProvidersTable() {
	auto filter = GetFilterTextLower();
	if (BeginTable("etwProvidersTable", 2, ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable |
		ImGuiTableFlags_ScrollX | ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg |
		ImGuiTableFlags_Hideable | ImGuiTableFlags_NoSavedSettings)) {
		TableSetupScrollFreeze(1, 1);
		TableSetupColumn("Name");
		TableSetupColumn("Guid");
		TableHeadersRow();

		for (const auto& provider : _providers) {
			if (!filter.IsEmpty()) {
				CString haystack((provider.Name + L" " + provider.Guid).c_str());
				haystack.MakeLower();
				if (haystack.Find(filter) < 0)
					continue;
			}

			TableNextRow();
			TableSetColumnIndex(0);
			Text("%ws", provider.Name.c_str());
			TableSetColumnIndex(1);
			Text("%ws", provider.Guid.c_str());
		}

		EndTable();
	}
}


