#pragma once

#include "ProcessManager.h"
#include "TabManager.h"
#include "Settings.h"
#include <string>
#include "WinSysProtocol.h"

struct ImFont;

class Globals {
public:
	Globals(HWND hWnd);

	static Globals& Get();
	static Globals* TryGet();
	ImFont* MonoFont{ nullptr };
	ImFont* RegFont{ nullptr };
	HWND GetMainHwnd() const;

	WinSys::ProcessManager ProcMgr;
	WinSys::ServiceManager SvcMgr;
	TabManager& GetTabManager();
	Settings& GetSettings();

	bool IsRemoteMode() const;
	void SetRemoteMode(bool remote);
	const std::string& GetRemoteAddress() const;
	void SetRemoteAddress(const std::string& addr);
	const SysInfoNet& GetRemoteSysInfo() const;
	void SetRemoteSysInfo(const SysInfoNet& info);

private:
	Settings _settings;
	inline static Globals* _globals{ nullptr };
	std::unique_ptr<TabManager> _tabs;
	HWND _hwnd;
	bool _remoteMode{ false };
	std::string _remoteAddress;
	SysInfoNet _remoteSysInfo{};
};

