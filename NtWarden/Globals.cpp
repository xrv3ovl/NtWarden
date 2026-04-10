#include "pch.h"
#include "Globals.h"
#include <assert.h>

Globals::Globals(HWND hwnd) : _hwnd(hwnd) {
	assert(_globals == nullptr);
	_globals = this;
	_tabs.reset(new TabManager);
}

Globals& Globals::Get() {
	assert(_globals);
	return *_globals;
}

Globals* Globals::TryGet() {
	return _globals;
}

HWND Globals::GetMainHwnd() const {
	return _hwnd;
}

TabManager& Globals::GetTabManager() {
	return *_tabs;
}

Settings& Globals::GetSettings() {
	return _settings;
}

bool Globals::IsRemoteMode() const {
	return _remoteMode;
}

void Globals::SetRemoteMode(bool remote) {
	_remoteMode = remote;
}

const std::string& Globals::GetRemoteAddress() const {
	return _remoteAddress;
}

void Globals::SetRemoteAddress(const std::string& addr) {
	_remoteAddress = addr;
}

const SysInfoNet& Globals::GetRemoteSysInfo() const {
	return _remoteSysInfo;
}

void Globals::SetRemoteSysInfo(const SysInfoNet& info) {
	_remoteSysInfo = info;
}
