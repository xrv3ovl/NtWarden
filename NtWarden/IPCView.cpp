#include "pch.h"
#include "imgui.h"
#include "IPCView.h"
#include "RemoteClient.h"
#include "LoggerView.h"

#include <algorithm>
#include <Rpc.h>

#pragma comment(lib, "Rpcrt4.lib")

using namespace ImGui;

namespace {
	std::wstring GuidToString(const UUID& guid) {
		WCHAR buffer[64]{};
		::StringFromGUID2(guid, buffer, _countof(buffer));
		return buffer;
	}

	std::wstring RpcWideToString(const RPC_WSTR text) {
		if (!text || !text[0])
			return {};
		return std::wstring(reinterpret_cast<const wchar_t*>(text));
	}

	bool MatchFilter(const CString& filter, const std::wstring& value) {
		if (filter.IsEmpty())
			return true;

		CString text(value.c_str());
		text.MakeLower();
		return text.Find(filter) >= 0;
	}
}

IPCView::IPCView() : ViewBase(0) {
	Refresh();
}

void IPCView::RefreshNow() {
	Refresh();
	MarkUpdated();
}

void IPCView::BuildWindow() {
	BuildToolBar();
	if (BeginTabBar("IpcTabBar")) {
		if (BeginTabItem("RPC Endpoints")) {
			BuildRpcTable();
			EndTabItem();
		}
		if (BeginTabItem("Named Pipes")) {
			BuildNamedPipesTable();
			EndTabItem();
		}
		EndTabBar();
	}
}

void IPCView::BuildToolBar() {
	DrawFilterToolbar();
}

void IPCView::Refresh() {
	_rpcEndpoints.clear();
	_namedPipes.clear();

	if (RemoteClient::IsConnected()) {
		auto remoteRpc = RemoteClient::GetRpcEndpoints();
		for (const auto& r : remoteRpc) {
			RpcEndpointInfo item;
			int chars;
			chars = ::MultiByteToWideChar(CP_UTF8, 0, r.InterfaceId, -1, nullptr, 0);
			item.InterfaceId.resize(chars > 0 ? chars - 1 : 0);
			if (chars > 0) ::MultiByteToWideChar(CP_UTF8, 0, r.InterfaceId, -1, item.InterfaceId.data(), chars);
			item.MajorVersion = r.MajorVersion;
			item.MinorVersion = r.MinorVersion;
			chars = ::MultiByteToWideChar(CP_UTF8, 0, r.Binding, -1, nullptr, 0);
			item.Binding.resize(chars > 0 ? chars - 1 : 0);
			if (chars > 0) ::MultiByteToWideChar(CP_UTF8, 0, r.Binding, -1, item.Binding.data(), chars);
			chars = ::MultiByteToWideChar(CP_UTF8, 0, r.Annotation, -1, nullptr, 0);
			item.Annotation.resize(chars > 0 ? chars - 1 : 0);
			if (chars > 0) ::MultiByteToWideChar(CP_UTF8, 0, r.Annotation, -1, item.Annotation.data(), chars);
			_rpcEndpoints.push_back(std::move(item));
		}

		auto remotePipes = RemoteClient::GetNamedPipes();
		for (const auto& p : remotePipes) {
			NamedPipeInfo item;
			int chars = ::MultiByteToWideChar(CP_UTF8, 0, p.Name, -1, nullptr, 0);
			item.Name.resize(chars > 0 ? chars - 1 : 0);
			if (chars > 0) ::MultiByteToWideChar(CP_UTF8, 0, p.Name, -1, item.Name.data(), chars);
			_namedPipes.push_back(std::move(item));
		}
	}
	else {
		RPC_EP_INQ_HANDLE inquiry = nullptr;
		auto status = ::RpcMgmtEpEltInqBegin(
			nullptr,
			RPC_C_EP_ALL_ELTS,
			nullptr,
			RPC_C_VERS_ALL,
			nullptr,
			&inquiry);

		if (status == RPC_S_OK) {
			for (;;) {
				RPC_IF_ID ifId{};
				RPC_BINDING_HANDLE binding = nullptr;
				UUID objectUuid{};
				RPC_WSTR annotation = nullptr;

				status = ::RpcMgmtEpEltInqNext(
					inquiry,
					&ifId,
					&binding,
					&objectUuid,
					&annotation);
				if (status != RPC_S_OK)
					break;

				RPC_WSTR bindingText = nullptr;
				if (::RpcBindingToStringBindingW(binding, &bindingText) == RPC_S_OK) {
					RpcEndpointInfo item;
					item.InterfaceId = GuidToString(ifId.Uuid);
					item.MajorVersion = ifId.VersMajor;
					item.MinorVersion = ifId.VersMinor;
					item.Binding = RpcWideToString(bindingText);
					item.Annotation = RpcWideToString(annotation);
					_rpcEndpoints.push_back(std::move(item));
					::RpcStringFreeW(&bindingText);
				}

				if (annotation)
					::RpcStringFreeW(&annotation);
				if (binding)
					::RpcBindingFree(&binding);
			}
			::RpcMgmtEpEltInqDone(&inquiry);
		}

		WIN32_FIND_DATAW data{};
		auto find = ::FindFirstFileW(L"\\\\.\\pipe\\*", &data);
		if (find != INVALID_HANDLE_VALUE) {
			do {
				if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
					NamedPipeInfo item;
					item.Name = data.cFileName;
					_namedPipes.push_back(std::move(item));
				}
			} while (::FindNextFileW(find, &data));
			::FindClose(find);
		}
	}

	std::sort(_rpcEndpoints.begin(), _rpcEndpoints.end(), [](const auto& left, const auto& right) {
		auto cmp = _wcsicmp(left.InterfaceId.c_str(), right.InterfaceId.c_str());
		if (cmp != 0)
			return cmp < 0;
		return _wcsicmp(left.Binding.c_str(), right.Binding.c_str()) < 0;
	});
	std::sort(_namedPipes.begin(), _namedPipes.end(), [](const auto& left, const auto& right) {
		return _wcsicmp(left.Name.c_str(), right.Name.c_str()) < 0;
	});

	LoggerView::AddLog(LoggerView::UserModeLog, "Enumerated %zu RPC endpoints and %zu named pipes", _rpcEndpoints.size(), _namedPipes.size());
}

void IPCView::BuildRpcTable() {
	Text("RPC Endpoints: %zu", _rpcEndpoints.size());
	Separator();

	auto filter = GetFilterTextLower();
	if (BeginTable("ipcRpcTable", 4, ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable |
		ImGuiTableFlags_ScrollX | ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg |
		ImGuiTableFlags_Hideable | ImGuiTableFlags_NoSavedSettings)) {
		TableSetupScrollFreeze(1, 1);
		TableSetupColumn("Interface");
		TableSetupColumn("Version", ImGuiTableColumnFlags_WidthFixed, 90.0f);
		TableSetupColumn("Binding");
		TableSetupColumn("Annotation");
		TableHeadersRow();

		for (const auto& item : _rpcEndpoints) {
			CStringW version;
			version.Format(L"%u.%u", item.MajorVersion, item.MinorVersion);
			auto versionText = std::wstring(version.GetString());
			if (!filter.IsEmpty() &&
				!MatchFilter(filter, item.InterfaceId) &&
				!MatchFilter(filter, versionText) &&
				!MatchFilter(filter, item.Binding) &&
				!MatchFilter(filter, item.Annotation))
				continue;

			TableNextRow();
			TableSetColumnIndex(0);
			Text("%ws", item.InterfaceId.c_str());
			TableSetColumnIndex(1);
			Text("%ws", versionText.c_str());
			TableSetColumnIndex(2);
			Text("%ws", item.Binding.c_str());
			TableSetColumnIndex(3);
			Text("%ws", item.Annotation.c_str());
		}

		EndTable();
	}
}

void IPCView::BuildNamedPipesTable() {
	Text("Named Pipes: %zu", _namedPipes.size());
	Separator();

	auto filter = GetFilterTextLower();
	if (BeginTable("ipcNamedPipesTable", 1, ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable |
		ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_NoSavedSettings)) {
		TableSetupScrollFreeze(1, 1);
		TableSetupColumn("Pipe Name");
		TableHeadersRow();

		for (const auto& item : _namedPipes) {
			if (!filter.IsEmpty() && !MatchFilter(filter, item.Name))
				continue;

			TableNextRow();
			TableSetColumnIndex(0);
			Text("%ws", item.Name.c_str());
		}

		EndTable();
	}
}
