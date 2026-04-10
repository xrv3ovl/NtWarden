#include "pch.h"
#include "imgui.h"
#include "CiPolicyView.h"
#include "RemoteClient.h"
#include "LoggerView.h"
#include <winternl.h>

using namespace ImGui;

typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(ULONG, PVOID, ULONG, PULONG);

static NtQuerySystemInformation_t GetNtQSI() {
	static auto fn = (NtQuerySystemInformation_t)::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
	return fn;
}

CiPolicyView::CiPolicyView() : ViewBase(0) {}

void CiPolicyView::RefreshNow() { ScanCiPolicy(); MarkUpdated(); }

void CiPolicyView::BuildWindow() { BuildCiPolicyPanel(); }

void CiPolicyView::ScanCiPolicy() {
	_ciPolicy = {};

	uint32_t ciOptions = 0;
	bool ok = false;

	if (RemoteClient::IsConnected()) {
		ok = RemoteClient::GetCiPolicy(ciOptions);
	}
	else {
		auto NtQSI = GetNtQSI();
		if (NtQSI) {
			struct SYSTEM_CODEINTEGRITY_INFORMATION {
				ULONG Length;
				ULONG CodeIntegrityOptions;
			} ciInfo{};
			ciInfo.Length = sizeof(ciInfo);
			ULONG retLen = 0;
			if (NtQSI(103, &ciInfo, sizeof(ciInfo), &retLen) == 0) {
				ciOptions = ciInfo.CodeIntegrityOptions;
				ok = true;
			}
		}
	}

	if (ok) {
		_ciPolicy.CiOptions = ciOptions;
		_ciPolicy.CodeIntegrityEnabled = (ciOptions & 0x01) != 0;
		_ciPolicy.TestSignEnabled = (ciOptions & 0x02) != 0;
		_ciPolicy.UmciEnabled = (ciOptions & 0x04) != 0;
		_ciPolicy.DebugModeEnabled = (ciOptions & 0x08) != 0;
		_ciPolicy.FlightSignedEnabled = (ciOptions & 0x10) != 0;
		_ciPolicy.HvciRunning = (ciOptions & 0x100) != 0;
	}

	_ciPolicy.Scanned = true;
}

void CiPolicyView::BuildCiPolicyPanel() {
	if (!_ciPolicy.Scanned) ScanCiPolicy();
	if (!_ciPolicy.Scanned) return;

	Text("Code Integrity (CI) Policy Status");
	Separator();

	Text("CI Options Raw: 0x%08X", _ciPolicy.CiOptions);
	Separator();

	struct CiFlag {
		const char* Name;
		unsigned long Mask;
		const char* Description;
		bool GoodWhenSet;
	};

	static const CiFlag flags[] = {
		{ "CODEINTEGRITY_OPTION_ENABLED",           0x01,  "Kernel-mode code integrity",       true },
		{ "CODEINTEGRITY_OPTION_TESTSIGN",           0x02,  "Test signing mode",                false },
		{ "CODEINTEGRITY_OPTION_UMCI_ENABLED",       0x04,  "User-mode code integrity (WDAC)",  true },
		{ "CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED",  0x08,  "CI debug mode",                    false },
		{ "CODEINTEGRITY_OPTION_FLIGHTSIGNING",      0x10,  "Flight-signed code allowed",       false },
		{ "CODEINTEGRITY_OPTION_UMCI_AUDITMODE",     0x20,  "UMCI audit mode",                  false },
		{ "CODEINTEGRITY_OPTION_UMCI_EXCLUSIONPATHS", 0x40, "UMCI exclusion paths",             false },
		{ "CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED",  0x100, "HVCI (Hypervisor CI)",             true },
		{ "CODEINTEGRITY_OPTION_HVCI_KMCI_AUDITMODE", 0x200, "HVCI audit mode",                false },
		{ "CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE", 0x400, "HVCI strict mode",              true },
		{ "CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED",   0x800, "IUM (Isolated User Mode)",         true },
	};

	if (BeginTable("ciFlagsTable", 4, ImGuiTableFlags_Resizable | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY)) {
		TableSetupScrollFreeze(1, 1);
		TableSetupColumn("Flag");
		TableSetupColumn("Value", ImGuiTableColumnFlags_WidthFixed, 60.0f);
		TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed, 70.0f);
		TableSetupColumn("Description");
		TableHeadersRow();

		for (auto& f : flags) {
			bool set = (_ciPolicy.CiOptions & f.Mask) != 0;
			TableNextRow();
			TableSetColumnIndex(0); Text("%s", f.Name);
			TableSetColumnIndex(1); Text("0x%X", f.Mask);
			TableSetColumnIndex(2);
			if (set == f.GoodWhenSet)
				TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), set ? "SET" : "OFF");
			else
				TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), set ? "SET" : "OFF");
			TableSetColumnIndex(3); TextDisabled("%s", f.Description);
		}
		EndTable();
	}
}
