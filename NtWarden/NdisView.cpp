#include "pch.h"
#include "imgui.h"
#include "NdisView.h"
#include "RemoteClient.h"
#include "LoggerView.h"
#include <iphlpapi.h>
#include <iptypes.h>

#pragma comment(lib, "Iphlpapi.lib")

using namespace ImGui;

namespace {
	std::wstring ToWide(const char* text) {
		if (text == nullptr || *text == 0)
			return L"";

		int chars = ::MultiByteToWideChar(CP_ACP, 0, text, -1, nullptr, 0);
		if (chars <= 0)
			return L"";

		std::wstring result(chars, L'\0');
		::MultiByteToWideChar(CP_ACP, 0, text, -1, result.data(), chars);
		if (!result.empty() && result.back() == L'\0')
			result.pop_back();
		return result;
	}
}

NdisView::NdisView() : ViewBase(0) {
	Refresh();
}

void NdisView::RefreshNow() {
	Refresh();
	MarkUpdated();
}

void NdisView::BuildWindow() {
	BuildToolBar();
	BuildTable();
}

void NdisView::Refresh() {
	_adapters.clear();

	if (RemoteClient::IsConnected()) {
		auto remote = RemoteClient::GetAdapters();
		for (const auto& a : remote) {
			AdapterInfo info;
			info.FriendlyName = ToWide(a.Name);
			info.Description = ToWide(a.Description);
			info.DnsSuffix = L"";
			info.MacAddress = ToWide(a.Mac);
			info.OperStatus = ToWide(a.Status);
			info.Type = ToWide(a.Type);
			info.IpAddress = ToWide(a.IpAddress);
			info.Gateway = ToWide(a.Gateway);
			_adapters.push_back(std::move(info));
		}
		LoggerView::AddLog(LoggerView::UserModeLog, "Loaded %d network adapters (remote)", static_cast<int>(_adapters.size()));
		return;
	}

	ULONG size = sizeof(IP_ADAPTER_INFO);
	std::vector<BYTE> buffer(size);
	auto adapters = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());
	DWORD error = ::GetAdaptersInfo(adapters, &size);
	if (error == ERROR_BUFFER_OVERFLOW) {
		buffer.resize(size);
		adapters = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());
		error = ::GetAdaptersInfo(adapters, &size);
	}

	if (error != NO_ERROR) {
		LoggerView::AddLog(LoggerView::UserModeLog, "GetAdaptersInfo failed: %u", error);
		return;
	}

	for (auto adapter = adapters; adapter; adapter = adapter->Next) {
		AdapterInfo info;
		info.FriendlyName = ToWide(adapter->AdapterName);
		info.Description = ToWide(adapter->Description);
		info.DnsSuffix = L"";
		info.MacAddress = FormatMacAddress(adapter->Address, adapter->AddressLength);
		info.OperStatus = adapter->DhcpEnabled ? L"DHCP" : L"Static";
		info.Type = IfTypeToString(adapter->Type);
		info.IpAddress = ToWide(adapter->IpAddressList.IpAddress.String);
		info.Gateway = ToWide(adapter->GatewayList.IpAddress.String);
		_adapters.push_back(std::move(info));
	}

	LoggerView::AddLog(LoggerView::UserModeLog, "Loaded %d network adapters", static_cast<int>(_adapters.size()));
}

void NdisView::BuildToolBar() {
	DrawFilterToolbar(200.0f);
}

void NdisView::BuildTable() {
	auto filter = GetFilterTextLower();
	if (BeginTable("ndisTable", 7, ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable |
		ImGuiTableFlags_ScrollX | ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_Hideable |
		ImGuiTableFlags_NoSavedSettings)) {
		TableSetupScrollFreeze(1, 1);
		TableSetupColumn("Name");
		TableSetupColumn("Description");
		TableSetupColumn("Type");
		TableSetupColumn("Status");
		TableSetupColumn("MAC");
		TableSetupColumn("IP Address");
		TableSetupColumn("Gateway");
		TableHeadersRow();

		for (const auto& adapter : _adapters) {
			if (!filter.IsEmpty()) {
				CString haystack((adapter.FriendlyName + L" " + adapter.Description + L" " + adapter.Type + L" " + adapter.OperStatus + L" " + adapter.MacAddress + L" " + adapter.IpAddress + L" " + adapter.Gateway).c_str());
				haystack.MakeLower();
				if (haystack.Find(filter) < 0)
					continue;
			}

			TableNextRow();
			TableSetColumnIndex(0);
			Text("%ws", adapter.FriendlyName.c_str());
			TableSetColumnIndex(1);
			Text("%ws", adapter.Description.c_str());
			TableSetColumnIndex(2);
			Text("%ws", adapter.Type.c_str());
			TableSetColumnIndex(3);
			Text("%ws", adapter.OperStatus.c_str());
			TableSetColumnIndex(4);
			Text("%ws", adapter.MacAddress.c_str());
			TableSetColumnIndex(5);
			Text("%ws", adapter.IpAddress.c_str());
			TableSetColumnIndex(6);
			Text("%ws", adapter.Gateway.c_str());
		}

		EndTable();
	}
}

std::wstring NdisView::FormatMacAddress(const BYTE* address, ULONG length) {
	if (address == nullptr || length == 0)
		return L"";

	CStringW text;
	for (ULONG i = 0; i < length; i++) {
		CStringW part;
		part.Format(L"%02X", address[i]);
		text += part;
		if (i + 1 < length)
			text += L"-";
	}
	return std::wstring(text);
}

PCWSTR NdisView::IfTypeToString(ULONG type) {
	switch (type) {
	case MIB_IF_TYPE_ETHERNET: return L"Ethernet";
	case IF_TYPE_IEEE80211: return L"Wi-Fi";
	case MIB_IF_TYPE_LOOPBACK: return L"Loopback";
	case MIB_IF_TYPE_PPP: return L"PPP";
	case MIB_IF_TYPE_SLIP: return L"SLIP";
	default: return L"Other";
	}
}
