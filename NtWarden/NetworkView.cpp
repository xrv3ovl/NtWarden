#include "pch.h"
#include "imgui.h"
#include "NetworkView.h"
#include "LoggerView.h"
#include "RemoteClient.h"

using namespace ImGui;

namespace {
	bool MatchFilter(const CString& filter, const std::wstring& value) {
		if (filter.IsEmpty())
			return true;

		CString text(value.c_str());
		text.MakeLower();
		return text.Find(filter) >= 0;
	}

	bool MatchFilter(const CString& filter, const CStringA& value) {
		if (filter.IsEmpty())
			return true;

		CString text(value);
		text.MakeLower();
		return text.Find(filter) >= 0;
	}
}

NetworkView::NetworkView() : ViewBase(2000) {
	_tracker.SetTrackingFlags(_trackingFlags);
}

void NetworkView::RefreshNow() {
	RefreshConnections();
	MarkUpdated();
}

void NetworkView::BuildWindow() {
	BuildToolBar();
	BuildConnectionsTable();
}

void NetworkView::BuildToolBar() {
	DrawFilterToolbar(160.0f);

	SameLine(0, 12);
	bool tcp = (_trackingFlags & WinSys::ConnectionType::Tcp) == WinSys::ConnectionType::Tcp;
	if (Checkbox("TCP", &tcp))
		_trackingFlags = tcp ? (_trackingFlags | WinSys::ConnectionType::Tcp) : (_trackingFlags & ~WinSys::ConnectionType::Tcp);

	SameLine();
	bool tcp6 = (_trackingFlags & WinSys::ConnectionType::TcpV6) == WinSys::ConnectionType::TcpV6;
	if (Checkbox("TCPv6", &tcp6))
		_trackingFlags = tcp6 ? (_trackingFlags | WinSys::ConnectionType::TcpV6) : (_trackingFlags & ~WinSys::ConnectionType::TcpV6);

	SameLine();
	bool udp = (_trackingFlags & WinSys::ConnectionType::Udp) == WinSys::ConnectionType::Udp;
	if (Checkbox("UDP", &udp))
		_trackingFlags = udp ? (_trackingFlags | WinSys::ConnectionType::Udp) : (_trackingFlags & ~WinSys::ConnectionType::Udp);

	SameLine();
	bool udp6 = (_trackingFlags & WinSys::ConnectionType::UdpV6) == WinSys::ConnectionType::UdpV6;
	if (Checkbox("UDPv6", &udp6))
		_trackingFlags = udp6 ? (_trackingFlags | WinSys::ConnectionType::UdpV6) : (_trackingFlags & ~WinSys::ConnectionType::UdpV6);

	SameLine(0, 12);
	Checkbox("Resolve Process Names", &_resolveProcesses);

	SameLine(0, 12);
	DrawUpdateIntervalToolbar("##NetworkUpdateInterval", false);

	_tracker.SetTrackingFlags(_trackingFlags);
}

namespace {
	std::wstring Utf8ToWideNet(const char* utf8) {
		if (!utf8 || !utf8[0]) return {};
		int size = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, nullptr, 0);
		std::wstring result(size - 1, 0);
		MultiByteToWideChar(CP_UTF8, 0, utf8, -1, result.data(), size);
		return result;
	}
}

void NetworkView::RefreshConnections() {
	if (RemoteClient::IsConnected()) {
		// Launch async fetch if not already pending
		if (!_remoteFetchPending) {
			_remoteFuture = std::async(std::launch::async, []() {
				return RemoteClient::GetConnections();
			});
			_remoteFetchPending = true;
		}
		// Check if async result is ready (non-blocking)
		if (_remoteFetchPending && _remoteFuture.valid() &&
			_remoteFuture.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
			auto netConns = _remoteFuture.get();
			_remoteFetchPending = false;
			_remoteConnections.clear();
			_remoteConnections.reserve(netConns.size());
			_processNames.clear();
			for (auto& nc : netConns) {
				auto c = std::make_shared<WinSys::Connection>();
				c->State = (MIB_TCP_STATE)nc.State;
				c->Pid = nc.Pid;
				c->Type = (WinSys::ConnectionType)nc.Type;
				c->LocalPort = nc.LocalPort;
				c->RemotePort = nc.RemotePort;
				memcpy(c->ucLocalAddress, nc.LocalAddress, 16);
				memcpy(c->ucRemoteAddress, nc.RemoteAddress, 16);
				c->ModuleName = Utf8ToWideNet(nc.ModuleName);
				_remoteConnections.push_back(c);
			}
			LoggerView::AddLog(LoggerView::UserModeLog, "Remote EnumConnections returned with %d items!", (int)netConns.size());
		}
		return;
	}

	if (_resolveProcesses) {
		_pm.EnumProcesses();
		_processNames.clear();
		for (const auto& process : _pm.GetProcesses())
			_processNames.insert({ process->Id, process->GetImageName() });
	}
	else {
		_processNames.clear();
	}

	auto count = _tracker.EnumConnections();
	LoggerView::AddLog(LoggerView::UserModeLog, "EnumConnections returned with %d items!", count);
}

void NetworkView::BuildConnectionsTable() {
	if (IsUpdateDue()) {
		RefreshConnections();
		MarkUpdated();
	}

	auto filter = GetFilterTextLower();
	if (BeginTable("netTable", 7, ImGuiTableFlags_Sortable |
		ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable |
		ImGuiTableFlags_ScrollX | ImGuiTableFlags_ScrollY |
		ImGuiTableFlags_RowBg | ImGuiTableFlags_Hideable | ImGuiTableFlags_NoSavedSettings)) {
		TableSetupScrollFreeze(1, 1);
		TableSetupColumn("Process", ImGuiTableColumnFlags_DefaultSort);
		TableSetupColumn("PID");
		TableSetupColumn("Protocol");
		TableSetupColumn("Local");
		TableSetupColumn("Remote");
		TableSetupColumn("State");
		TableSetupColumn("Module");
		TableHeadersRow();

		auto specs = TableGetSortSpecs();
		if (specs && specs->SpecsDirty) {
			_specs = specs->Specs;
			specs->SpecsDirty = false;
		}

		const auto& connections = RemoteClient::IsConnected() ? _remoteConnections : _tracker.GetConnections();
		std::vector<int> visibleRows;
		visibleRows.reserve(connections.size());
		for (int i = 0; i < static_cast<int>(connections.size()); i++) {
			const auto& conn = connections[i];
			auto processIt = _processNames.find(conn->Pid);
			const auto processName = processIt != _processNames.end() ? processIt->second : std::wstring(L"<unknown>");
			const auto local = FormatEndpoint(*conn, true);
			const auto remote = FormatEndpoint(*conn, false);
			const auto protocol = std::wstring(ProtocolToString(conn->Type));
			const auto moduleName = conn->ModuleName;
			CStringA pidText;
			pidText.Format("%u", conn->Pid);

			if (filter.IsEmpty() ||
				MatchFilter(filter, processName) ||
				MatchFilter(filter, local) ||
				MatchFilter(filter, remote) ||
				MatchFilter(filter, protocol) ||
				MatchFilter(filter, moduleName) ||
				MatchFilter(filter, pidText)) {
				visibleRows.push_back(i);
			}
		}

		ImGuiListClipper clipper;
		clipper.Begin(static_cast<int>(visibleRows.size()));
		while (clipper.Step()) {
			for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; row++) {
				const auto& conn = connections[visibleRows[row]];
				auto processIt = _processNames.find(conn->Pid);
				const auto processName = processIt != _processNames.end() ? processIt->second : std::wstring(L"<unknown>");
				const auto local = FormatEndpoint(*conn, true);
				const auto remote = FormatEndpoint(*conn, false);
				const auto state = StateToString(conn->State);
				const auto protocol = ProtocolToString(conn->Type);

				TableNextRow();

				TableSetColumnIndex(0);
				Text("%ws", processName.c_str());

				TableSetColumnIndex(1);
				Text("%u", conn->Pid);

				TableSetColumnIndex(2);
				Text("%ws", protocol);

				TableSetColumnIndex(3);
				Text("%ws", local.c_str());

				TableSetColumnIndex(4);
				Text("%ws", remote.c_str());

				TableSetColumnIndex(5);
				Text("%ws", state);

				TableSetColumnIndex(6);
				Text("%ws", conn->ModuleName.empty() ? L"" : conn->ModuleName.c_str());
			}
		}

		EndTable();
	}
}

PCWSTR NetworkView::ProtocolToString(WinSys::ConnectionType type) {
	using enum WinSys::ConnectionType;
	switch (type) {
	case Tcp: return L"TCP";
	case TcpV6: return L"TCPv6";
	case Udp: return L"UDP";
	case UdpV6: return L"UDPv6";
	default: return L"Unknown";
	}
}

PCWSTR NetworkView::StateToString(MIB_TCP_STATE state) {
	switch (state) {
	case MIB_TCP_STATE_CLOSED: return L"Closed";
	case MIB_TCP_STATE_LISTEN: return L"Listen";
	case MIB_TCP_STATE_SYN_SENT: return L"SYN Sent";
	case MIB_TCP_STATE_SYN_RCVD: return L"SYN Received";
	case MIB_TCP_STATE_ESTAB: return L"Established";
	case MIB_TCP_STATE_FIN_WAIT1: return L"FIN Wait 1";
	case MIB_TCP_STATE_FIN_WAIT2: return L"FIN Wait 2";
	case MIB_TCP_STATE_CLOSE_WAIT: return L"Close Wait";
	case MIB_TCP_STATE_CLOSING: return L"Closing";
	case MIB_TCP_STATE_LAST_ACK: return L"Last ACK";
	case MIB_TCP_STATE_TIME_WAIT: return L"Time Wait";
	case MIB_TCP_STATE_DELETE_TCB: return L"Delete TCB";
	default: return L"";
	}
}

std::wstring NetworkView::FormatAddress(const WinSys::Connection& conn, bool local) {
	CStringW text;
	const auto type = conn.Type;
	if (type == WinSys::ConnectionType::Tcp || type == WinSys::ConnectionType::Udp) {
		DWORD address = local ? conn.LocalAddress : conn.RemoteAddress;
		auto bytes = reinterpret_cast<const BYTE*>(&address);
		text.Format(L"%u.%u.%u.%u", bytes[0], bytes[1], bytes[2], bytes[3]);
		return std::wstring(text);
	}

	const UCHAR* bytes = local ? conn.ucLocalAddress : conn.ucRemoteAddress;
	text.Format(L"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
		bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
		bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
	return std::wstring(text);
}

std::wstring NetworkView::FormatEndpoint(const WinSys::Connection& conn, bool local) {
	auto address = FormatAddress(conn, local);
	if ((!local && (conn.Type == WinSys::ConnectionType::Udp || conn.Type == WinSys::ConnectionType::UdpV6)) ||
		(!local && conn.RemotePort == 0 && (conn.Type == WinSys::ConnectionType::Tcp || conn.Type == WinSys::ConnectionType::TcpV6)))
		return address;

	CStringW endpoint;
	endpoint.Format(L"%ws:%u", address.c_str(), FormatPort(local ? conn.LocalPort : conn.RemotePort));
	return std::wstring(endpoint);
}

uint16_t NetworkView::FormatPort(DWORD port) {
	return static_cast<uint16_t>(((port & 0xff) << 8) | ((port >> 8) & 0xff));
}
