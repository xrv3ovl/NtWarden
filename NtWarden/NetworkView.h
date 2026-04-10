#pragma once

#include "ActiveConnectionTracker.h"
#include "ProcessManager.h"
#include "ProcessInfo.h"
#include "ViewBase.h"
#include <future>
#include "WinSysProtocol.h"

class NetworkView : public ViewBase {
public:
	NetworkView();

	void BuildWindow();
	void RefreshNow();

private:
	void BuildToolBar();
	void BuildConnectionsTable();
	void RefreshConnections();

	static PCWSTR ProtocolToString(WinSys::ConnectionType type);
	static PCWSTR StateToString(MIB_TCP_STATE state);
	static std::wstring FormatAddress(const WinSys::Connection& conn, bool local);
	static std::wstring FormatEndpoint(const WinSys::Connection& conn, bool local);
	static uint16_t FormatPort(DWORD port);

private:
	WinSys::ActiveConnectionTracker _tracker;
	WinSys::ProcessManager _pm;
	std::unordered_map<DWORD, std::wstring> _processNames;
	const ImGuiTableColumnSortSpecs* _specs{ nullptr };
	WinSys::ConnectionType _trackingFlags{ WinSys::ConnectionType::All };
	bool _resolveProcesses{ true };

	// Remote mode: store connections locally
	std::vector<std::shared_ptr<WinSys::Connection>> _remoteConnections;

	// Async remote fetch
	std::future<std::vector<ConnectionNet>> _remoteFuture;
	bool _remoteFetchPending = false;
};
