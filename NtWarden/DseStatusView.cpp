#include "pch.h"
#include "imgui.h"
#include "DseStatusView.h"
#include "LoggerView.h"
#include "RemoteClient.h"
#include <winternl.h>

using namespace ImGui;

typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(ULONG, PVOID, ULONG, PULONG);

static NtQuerySystemInformation_t GetNtQSI() {
	static auto fn = (NtQuerySystemInformation_t)::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
	return fn;
}

DseStatusView::DseStatusView() : ViewBase(0) {}

void DseStatusView::RefreshNow() { ScanDseStatus(); MarkUpdated(); }

void DseStatusView::BuildWindow() { BuildDsePanel(); }

void DseStatusView::DecodeDseInfo(unsigned long ciOptions, unsigned long secureBootReg, unsigned long vbsReg) {
	_dseInfo.CodeIntegrityOptions = ciOptions;
	_dseInfo.DseEnabled = (ciOptions & 0x01) != 0;
	_dseInfo.TestSigningEnabled = (ciOptions & 0x02) != 0;
	_dseInfo.HvciEnabled = (ciOptions & 0x100) != 0;
	_dseInfo.SecureBootEnabled = (secureBootReg != 0xFFFFFFFF) ? (secureBootReg != 0) : false;
	_dseInfo.VbsEnabled = (vbsReg != 0xFFFFFFFF) ? (vbsReg != 0) : false;
	_dseInfo.Scanned = true;
}

void DseStatusView::ScanDseStatus() {
	_dseInfo = {};

	if (RemoteClient::IsConnected()) {
		DseStatusNet net{};
		if (RemoteClient::GetDseStatus(net))
			DecodeDseInfo(net.gCiOptionsValue, net.SecureBootRegValue, net.VbsRegValue);
		return;
	}

	unsigned long ciOptions = 0;
	auto NtQSI = GetNtQSI();
	if (NtQSI) {
		struct SYSTEM_CODEINTEGRITY_INFORMATION {
			ULONG Length;
			ULONG CodeIntegrityOptions;
		} ciInfo{};
		ciInfo.Length = sizeof(ciInfo);
		ULONG retLen = 0;
		if (NtQSI(103, &ciInfo, sizeof(ciInfo), &retLen) == 0)
			ciOptions = ciInfo.CodeIntegrityOptions;
	}

	unsigned long secureBootReg = 0xFFFFFFFF;
	HKEY hKey = nullptr;
	if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
		DWORD val = 0, size = sizeof(val);
		if (::RegQueryValueExW(hKey, L"UEFISecureBootEnabled", nullptr, nullptr, (LPBYTE)&val, &size) == ERROR_SUCCESS)
			secureBootReg = val;
		::RegCloseKey(hKey);
	}

	unsigned long vbsReg = 0xFFFFFFFF;
	if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
		DWORD val = 0, size = sizeof(val);
		if (::RegQueryValueExW(hKey, L"EnableVirtualizationBasedSecurity", nullptr, nullptr, (LPBYTE)&val, &size) == ERROR_SUCCESS)
			vbsReg = val;
		::RegCloseKey(hKey);
	}

	DecodeDseInfo(ciOptions, secureBootReg, vbsReg);
}

void DseStatusView::BuildDsePanel() {
	if (!_dseInfo.Scanned) ScanDseStatus();
	if (!_dseInfo.Scanned) return;

	Text("Driver Signature Enforcement (DSE) Status");
	Separator();

	Text("Code Integrity Options: 0x%08X", _dseInfo.CodeIntegrityOptions);
	Separator();

	auto StatusLine = [](const char* label, bool enabled, bool goodWhenEnabled) {
		Text("  %s: ", label);
		SameLine(0, 0);
		if (enabled == goodWhenEnabled)
			TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), enabled ? "Enabled" : "Disabled");
		else
			TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), enabled ? "Enabled" : "Disabled");
	};

	StatusLine("DSE (Code Integrity)", _dseInfo.DseEnabled, true);
	StatusLine("Test Signing", _dseInfo.TestSigningEnabled, false);
	StatusLine("Secure Boot", _dseInfo.SecureBootEnabled, true);
	StatusLine("HVCI (Hypervisor CI)", _dseInfo.HvciEnabled, true);
	StatusLine("VBS (Virtualization)", _dseInfo.VbsEnabled, true);

	Separator();
	if (!_dseInfo.DseEnabled)
		TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "WARNING: DSE is DISABLED - unsigned drivers can load!");
	if (_dseInfo.TestSigningEnabled)
		TextColored(ImVec4(1.0f, 0.6f, 0.0f, 1.0f), "WARNING: Test signing is enabled - test-signed drivers allowed.");
	if (_dseInfo.DseEnabled && !_dseInfo.TestSigningEnabled && _dseInfo.SecureBootEnabled)
		TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), "System is well-protected: DSE + Secure Boot active.");
}
