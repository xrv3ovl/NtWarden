#include "pch.h"
#include "imgui.h"
#include "ProcessObjectsView.h"
#include <algorithm>
#include "SortHelper.h"
#include "FormatHelper.h"
#include "ImGuiExt.h"
#include "LoggerView.h"
#include "RemoteClient.h"

#include <Psapi.h>
#pragma comment(lib, "psapi.lib")

using namespace ImGui;

ProcessObjectsView::ProcessObjectsView() : ViewBase(0) {}

const char* ProcessObjectsView::ProtectionSignerToString(unsigned char signer) {
	switch (signer) {
	case 0: return "None";
	case 1: return "Authenticode";
	case 2: return "CodeGen";
	case 3: return "Antimalware";
	case 4: return "Lsa";
	case 5: return "Windows";
	case 6: return "WinTcb";
	case 7: return "WinSystem";
	case 8: return "App";
	default: return "Unknown";
	}
}

const char* ProcessObjectsView::ProtectionTypeToString(unsigned char type) {
	switch (type) {
	case 0: return "None";
	case 1: return "ProtectedLight";
	case 2: return "Protected";
	default: return "Unknown";
	}
}

ProcessObjectsView::PdbResult ProcessObjectsView::ResolveEprocessOffsetsAsync() {
	PdbResult result;

	// Use a unique pseudo-handle to avoid conflicts with SymbolView's SymInitialize
	SymbolHelper symbolHelper((HANDLE)0x4321);
	if (!symbolHelper.IsInitialized()) {
		result.status = "Symbol engine init failed";
		LoggerView::AddLog(LoggerView::UserModeLog, "Process Objects: %s", result.status.c_str());
		return result;
	}

	DWORD64 modBase = 0;
	DWORD imageSize = 0;
	std::wstring pdbPath;
	wchar_t cacheDir[MAX_PATH]{};
	GetCurrentDirectoryW(MAX_PATH, cacheDir);
	std::wstring symbolCacheDir = std::wstring(cacheDir) + L"\\Symbols";

	if (RemoteClient::IsConnected()) {
		// Remote: get kernel base info from the server
		KernelBaseInfoNet kbInfo{};
		if (!RemoteClient::GetKernelBase(kbInfo) || kbInfo.KernelBase == 0) {
			result.status = "Remote kernel base query failed";
			LoggerView::AddLog(LoggerView::UserModeLog, "Process Objects: %s", result.status.c_str());
			return result;
		}

		modBase = kbInfo.KernelBase;
		imageSize = kbInfo.ImageSize;

		LoggerView::AddLog(LoggerView::UserModeLog, "Process Objects: remote ntoskrnl base=0x%llX, imageSize=0x%X",
			(unsigned long long)modBase, imageSize);

		GUID pdbGuid;
		memcpy(&pdbGuid, kbInfo.PdbGuid, sizeof(GUID));
		LoggerView::AddLog(LoggerView::UserModeLog, "Process Objects: Downloading PDB from symbol server (remote signature)...");
		pdbPath = SymbolHelper::DownloadPdbBySignature(pdbGuid, kbInfo.PdbAge, kbInfo.PdbFileName, symbolCacheDir);
	}
	else {
		// Local: use EnumDeviceDrivers
		LPVOID drivers[1024]{};
		DWORD cbNeeded = 0;
		if (!EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) {
			result.status = "EnumDeviceDrivers failed";
			LoggerView::AddLog(LoggerView::UserModeLog, "Process Objects: %s", result.status.c_str());
			return result;
		}

		LPVOID ntoskrnlBase = drivers[0];
		wchar_t driverPath[MAX_PATH]{};
		if (!GetDeviceDriverFileNameW(ntoskrnlBase, driverPath, MAX_PATH)) {
			result.status = "GetDeviceDriverFileName failed";
			LoggerView::AddLog(LoggerView::UserModeLog, "Process Objects: %s", result.status.c_str());
			return result;
		}

		std::wstring fullPath = driverPath;
		if (fullPath.find(L"\\SystemRoot\\") == 0) {
			wchar_t winDir[MAX_PATH];
			GetWindowsDirectoryW(winDir, MAX_PATH);
			fullPath = winDir + fullPath.substr(11);
		}

		LoggerView::AddLog(LoggerView::UserModeLog, "Process Objects: ntoskrnl at %ws, base=0x%llX",
			fullPath.c_str(), (unsigned long long)ntoskrnlBase);

		LoggerView::AddLog(LoggerView::UserModeLog, "Process Objects: Downloading PDB from symbol server...");
		pdbPath = SymbolHelper::DownloadPdb(fullPath, symbolCacheDir);

		{
			HANDLE hFile = CreateFileW(fullPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
			if (hFile != INVALID_HANDLE_VALUE) {
				HANDLE hMapping = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
				if (hMapping) {
					auto* base = static_cast<BYTE*>(MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0));
					if (base) {
						auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
						if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
							auto* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dosHeader->e_lfanew);
							if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
								imageSize = reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(&ntHeaders->OptionalHeader)->SizeOfImage;
							else
								imageSize = ntHeaders->OptionalHeader.SizeOfImage;
						}
						UnmapViewOfFile(base);
					}
					CloseHandle(hMapping);
				}
				CloseHandle(hFile);
			}
		}

		modBase = (DWORD64)ntoskrnlBase;
	}

	if (pdbPath.empty()) {
		result.status = "PDB download failed";
		LoggerView::AddLog(LoggerView::UserModeLog, "Process Objects: %s", result.status.c_str());
		return result;
	}

	if (!symbolHelper.LoadSymbolsFromPdb(pdbPath, L"ntoskrnl.exe", modBase, imageSize)) {
		result.status = "Symbols loaded, but required kernel types were not available";
		LoggerView::AddLog(LoggerView::UserModeLog, "Process Objects: %s", result.status.c_str());
		return result;
	}

	// Resolve EPROCESS offsets
	EPROCESS_OFFSETS offsets = {};
	DWORD64 base = modBase;
	const ULONG INVALID = (ULONG)-1;

	offsets.ProtectionOffset = symbolHelper.GetStructMemberOffset(base, L"_EPROCESS", L"Protection");
	offsets.TokenOffset = symbolHelper.GetStructMemberOffset(base, L"_EPROCESS", L"Token");
	offsets.PebOffset = symbolHelper.GetStructMemberOffset(base, L"_EPROCESS", L"Peb");
	offsets.DirectoryTableBaseOffset = symbolHelper.GetStructMemberOffset(base, L"_KPROCESS", L"DirectoryTableBase");
	offsets.FlagsOffset = symbolHelper.GetStructMemberOffset(base, L"_EPROCESS", L"Flags");
	offsets.Flags2Offset = symbolHelper.GetStructMemberOffset(base, L"_EPROCESS", L"Flags2");
	offsets.SignatureLevelOffset = symbolHelper.GetStructMemberOffset(base, L"_EPROCESS", L"SignatureLevel");
	offsets.SectionSignatureLevelOffset = symbolHelper.GetStructMemberOffset(base, L"_EPROCESS", L"SectionSignatureLevel");
	offsets.ObjectTableOffset = symbolHelper.GetStructMemberOffset(base, L"_EPROCESS", L"ObjectTable");
	offsets.MitigationFlagsOffset = symbolHelper.GetStructMemberOffset(base, L"_EPROCESS", L"MitigationFlags");
	offsets.MitigationFlags2Offset = symbolHelper.GetStructMemberOffset(base, L"_EPROCESS", L"MitigationFlags2");
	offsets.ActiveProcessLinksOffset = symbolHelper.GetStructMemberOffset(base, L"_EPROCESS", L"ActiveProcessLinks");
	offsets.UniqueProcessIdOffset = symbolHelper.GetStructMemberOffset(base, L"_EPROCESS", L"UniqueProcessId");

	int resolved = 0;
	int total = 13;
	if (offsets.ProtectionOffset != INVALID) resolved++;
	if (offsets.TokenOffset != INVALID) resolved++;
	if (offsets.PebOffset != INVALID) resolved++;
	if (offsets.DirectoryTableBaseOffset != INVALID) resolved++;
	if (offsets.FlagsOffset != INVALID) resolved++;
	if (offsets.Flags2Offset != INVALID) resolved++;
	if (offsets.SignatureLevelOffset != INVALID) resolved++;
	if (offsets.SectionSignatureLevelOffset != INVALID) resolved++;
	if (offsets.ObjectTableOffset != INVALID) resolved++;
	if (offsets.MitigationFlagsOffset != INVALID) resolved++;
	if (offsets.MitigationFlags2Offset != INVALID) resolved++;
	if (offsets.ActiveProcessLinksOffset != INVALID) resolved++;
	if (offsets.UniqueProcessIdOffset != INVALID) resolved++;

	LoggerView::AddLog(LoggerView::UserModeLog,
		"Process Objects: Resolved %d/%d EPROCESS offsets from PDB "
		"(Protection=0x%X Token=0x%X Peb=0x%X DirBase=0x%X Flags=0x%X ObjectTable=0x%X SigLevel=0x%X ActiveLinks=0x%X PID=0x%X)",
		resolved, total,
		offsets.ProtectionOffset, offsets.TokenOffset, offsets.PebOffset,
		offsets.DirectoryTableBaseOffset, offsets.FlagsOffset,
		offsets.ObjectTableOffset, offsets.SignatureLevelOffset,
		offsets.ActiveProcessLinksOffset, offsets.UniqueProcessIdOffset);

	if (resolved > 0) {
		offsets.Valid = 1;
		bool offsetsSent = RemoteClient::IsConnected() ? RemoteClient::SendEprocessOffsets(offsets) : DriverHelper::SendEprocessOffsets(offsets);
		if (offsetsSent) {
			result.resolved = true;
			result.hasDetailedFields = true;
			char buf[64];
			sprintf_s(buf, "PDB: %d/%d offsets resolved", resolved, total);
			result.status = buf;
			LoggerView::AddLog(LoggerView::UserModeLog, "Process Objects: EPROCESS offsets sent to driver successfully");
		}
		else {
			result.status = "Failed to send offsets to driver";
			LoggerView::AddLog(LoggerView::UserModeLog, "Process Objects: %s", result.status.c_str());
		}
	}
	else {
		result.status = "No offsets resolved from PDB";
		LoggerView::AddLog(LoggerView::UserModeLog, "Process Objects: %s", result.status.c_str());
	}

	return result;
}

void ProcessObjectsView::ResolveEprocessOffsets() {
	if (_pdbResolutionAttempted)
		return;
	_pdbResolutionAttempted = true;
	_pdbResolving = true;
	_pdbStatus = "Resolving PDB symbols...";
	LoggerView::AddLog(LoggerView::UserModeLog, "Process Objects: Starting async PDB resolution...");
	_pdbFuture = std::async(std::launch::async, ResolveEprocessOffsetsAsync);
}

void ProcessObjectsView::RefreshProcesses() {
	auto entries = RemoteClient::IsConnected() ? RemoteClient::GetProcessObjects() : DriverHelper::GetProcessObjects();
	_processes.clear();
	_processes.reserve(entries.size());

	for (auto& e : entries) {
		auto row = std::make_shared<ProcessRow>();
		row->EprocessAddress = e.EprocessAddress;
		row->ProcessId = e.ProcessId;
		row->ParentProcessId = e.ParentProcessId;
		row->SessionId = e.SessionId;
		row->HandleCount = e.HandleCount;
		row->ThreadCount = e.ThreadCount;
		row->CreateTime = e.CreateTime;
		row->ImageName = e.ImageName;
		row->IsProtected = e.IsProtected != 0;
		row->IsProtectedLight = e.IsProtectedLight != 0;
		row->IsWow64 = e.IsWow64 != 0;
		/* PDB-resolved fields */
		row->Protection = e.Protection;
		row->TokenAddress = e.TokenAddress;
		row->PebAddress = e.PebAddress;
		row->DirectoryTableBase = e.DirectoryTableBase;
		row->ObjectTableAddress = e.ObjectTableAddress;
		row->Flags = e.Flags;
		row->Flags2 = e.Flags2;
		row->SignatureLevel = e.SignatureLevel;
		row->SectionSignatureLevel = e.SectionSignatureLevel;
		row->ProtectionType = e.ProtectionType;
		row->ProtectionSigner = e.ProtectionSigner;
		row->MitigationFlags = e.MitigationFlags;
		row->MitigationFlags2 = e.MitigationFlags2;
		_processes.push_back(std::move(row));
	}

	_loaded = true;
	LoggerView::AddLog(LoggerView::UserModeLog, "Enumerated %zu kernel process objects (EPROCESS)", _processes.size());
}

void ProcessObjectsView::DoSort(int col, bool asc) {
	std::sort(_processes.begin(), _processes.end(), [=](const auto& a, const auto& b) {
		switch (col) {
		case 0: return SortHelper::SortStrings(a->ImageName, b->ImageName, asc);
		case 1: return SortHelper::SortNumbers(a->ProcessId, b->ProcessId, asc);
		case 2: return SortHelper::SortNumbers(a->EprocessAddress, b->EprocessAddress, asc);
		case 3: return SortHelper::SortNumbers(a->ParentProcessId, b->ParentProcessId, asc);
		case 4: return SortHelper::SortNumbers(a->SessionId, b->SessionId, asc);
		case 5: return SortHelper::SortNumbers(a->ThreadCount, b->ThreadCount, asc);
		case 6: return SortHelper::SortNumbers(a->HandleCount, b->HandleCount, asc);
		case 7: return SortHelper::SortNumbers(a->CreateTime, b->CreateTime, asc);
		case 8: return SortHelper::SortNumbers((int)a->ProtectionSigner, (int)b->ProtectionSigner, asc);
		case 9: return SortHelper::SortNumbers((int)a->IsWow64, (int)b->IsWow64, asc);
		case 10: return SortHelper::SortNumbers(a->TokenAddress, b->TokenAddress, asc);
		case 11: return SortHelper::SortNumbers(a->PebAddress, b->PebAddress, asc);
		case 12: return SortHelper::SortNumbers(a->DirectoryTableBase, b->DirectoryTableBase, asc);
		case 13: return SortHelper::SortNumbers((int)a->SignatureLevel, (int)b->SignatureLevel, asc);
		case 14: return SortHelper::SortNumbers(a->Flags, b->Flags, asc);
		case 15: return SortHelper::SortNumbers(a->ObjectTableAddress, b->ObjectTableAddress, asc);
		case 16: return SortHelper::SortNumbers(a->MitigationFlags, b->MitigationFlags, asc);
		}
		return false;
	});
}

void ProcessObjectsView::BuildWindow() {
	if (!_loaded)
		RefreshProcesses();

	// Resolve EPROCESS offsets from PDB on first use
	if (!_pdbResolutionAttempted)
		ResolveEprocessOffsets();

	// Poll async PDB resolution
	if (_pdbResolving && _pdbFuture.valid() &&
		_pdbFuture.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
		auto result = _pdbFuture.get();
		_pdbOffsetsResolved = result.resolved;
		_pdbHasDetailedFields = result.hasDetailedFields;
		_pdbStatus = result.status;
		_pdbResolving = false;

		// Auto-refresh now that offsets are available to the driver
		if (_pdbOffsetsResolved)
			RefreshProcesses();
	}

	// Poll async cross-check
	if (_crossCheckRunning && _crossCheckFuture.valid() &&
		_crossCheckFuture.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
		auto result = _crossCheckFuture.get();
		_crossCheckHeader = result.header;
		_crossCheckEntries.clear();
		_crossCheckEntries.reserve(result.entries.size());
		for (auto& e : result.entries) {
			CrossCheckRow row;
			row.ProcessId = e.ProcessId;
			row.EprocessAddress = e.EprocessAddress;
			row.ImageName = e.ImageName;
			row.Sources = e.Sources;
			_crossCheckEntries.push_back(std::move(row));
		}
		_crossCheckRan = true;
		_crossCheckRunning = false;
		_showCrossCheck = _crossCheckHeader.SuspiciousCount > 0;
		LoggerView::AddLog(LoggerView::UserModeLog,
			"DKOM Cross-Check: ActiveLinks=%u, CidTable=%u, Total=%u, Suspicious=%u",
			_crossCheckHeader.ActiveLinksCount, _crossCheckHeader.CidTableCount,
			_crossCheckHeader.TotalEntries, _crossCheckHeader.SuspiciousCount);
	}

	BuildToolBar();
	BuildCrossCheckPanel();
	BuildTable();
	BuildDetailsPanel();
}

void ProcessObjectsView::BuildToolBar() {
	// PDB status indicator
	if (!_pdbStatus.empty()) {
		if (_pdbResolving)
			TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "%s", _pdbStatus.c_str());
		else if (_pdbOffsetsResolved)
			TextColored(ImVec4(0.0f, 1.0f, 0.4f, 1.0f), "%s", _pdbStatus.c_str());
		else
			TextColored(ImVec4(1.0f, 0.4f, 0.0f, 1.0f), "%s", _pdbStatus.c_str());
		SameLine();
	}

	Separator();
	if (Button("Refresh")) {
		RefreshProcesses();
		if (_specs)
			DoSort(_specs->ColumnIndex, _specs->SortDirection == ImGuiSortDirection_Ascending);
	}
	SameLine();
	DrawFilterToolbar();
	SameLine();
	Separator();
	SameLine();

	if (_pdbOffsetsResolved) {
		if (Button(_crossCheckRunning ? "Running..." : "DKOM Cross-Check")) {
			if (!_crossCheckRunning)
				RunCrossCheck();
		}
		if (_crossCheckRan) {
			SameLine();
			if (_crossCheckHeader.SuspiciousCount > 0)
				TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "%u HIDDEN", _crossCheckHeader.SuspiciousCount);
			else
				TextColored(ImVec4(0.0f, 1.0f, 0.4f, 1.0f), "Clean (%u procs)", _crossCheckHeader.ActiveLinksCount);
			SameLine();
			Checkbox("Show##crosscheck", &_showCrossCheck);
		}
	}
	else {
		TextDisabled("Cross-check requires PDB offsets");
	}
}

void ProcessObjectsView::BuildTable() {
	int numCols = _pdbHasDetailedFields ? 17 : 10;

	if (BeginTable("procObjTable", numCols,
		ImGuiTableFlags_Sortable | ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable |
		ImGuiTableFlags_ScrollX | ImGuiTableFlags_ScrollY |
		ImGuiTableFlags_RowBg | ImGuiTableFlags_Hideable | ImGuiTableFlags_NoSavedSettings)) {

		TableSetupScrollFreeze(2, 1);
		TableSetupColumn("Image Name", ImGuiTableColumnFlags_NoHide | ImGuiTableColumnFlags_NoReorder);
		TableSetupColumn("PID", ImGuiTableColumnFlags_NoHide | ImGuiTableColumnFlags_NoReorder);
		TableSetupColumn("EPROCESS");
		TableSetupColumn("Parent PID");
		TableSetupColumn("Session");
		TableSetupColumn("Threads");
		TableSetupColumn("Handles");
		TableSetupColumn("Create Time");
		TableSetupColumn("Protection");
		TableSetupColumn("WoW64");

		if (_pdbHasDetailedFields) {
			TableSetupColumn("Token");
			TableSetupColumn("PEB");
			TableSetupColumn("DirBase (CR3)");
			TableSetupColumn("Signature Level");
			TableSetupColumn("Flags");
			TableSetupColumn("Object Table");
			TableSetupColumn("Mitigation Flags");
		}

		TableHeadersRow();

		auto filter = GetFilterTextLower();
		std::vector<int> indices;
		indices.reserve(_processes.size());

		auto total = static_cast<int>(_processes.size());
		for (int i = 0; i < total; i++) {
			auto& p = _processes[i];
			p->Filtered = false;
			if (!filter.IsEmpty()) {
				CString name(p->ImageName.c_str());
				name.MakeLower();
				if (name.Find(filter) < 0) {
					p->Filtered = true;
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

		ImGuiListClipper clipper;
		auto count = static_cast<int>(indices.size());
		clipper.Begin(count);

		CStringA str;

		while (clipper.Step()) {
			for (int j = clipper.DisplayStart; j < clipper.DisplayEnd; j++) {
				int i = indices[j];
				auto& p = _processes[i];
				if (p->Filtered) {
					clipper.ItemsCount--;
					continue;
				}
				TableNextRow();

				bool isProtected = p->IsProtected || p->IsProtectedLight;
				bool isWinTcb = p->ProtectionSigner == 6;

				if (isWinTcb)
					PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.3f, 0.3f, 1.0f));
				else if (isProtected)
					PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.65f, 0.0f, 1.0f));

				TableSetColumnIndex(0);
				str.Format("%s##po%d", p->ImageName.c_str(), i);
				Selectable(str, _selectedProcess == p, ImGuiSelectableFlags_SpanAllColumns);
				if (IsItemClicked())
					_selectedProcess = p;
				if (IsItemClicked(ImGuiMouseButton_Right))
					_selectedProcess = p;

				// Right-click context menu
				if (BeginPopupContextItem()) {
					if (BeginMenu("Copy")) {
						if (MenuItem("Image Name")) {
							SetClipboardText(p->ImageName.c_str());
						}
						if (MenuItem("PID")) {
							char buf[32];
							sprintf_s(buf, "%u", p->ProcessId);
							SetClipboardText(buf);
						}
						if (MenuItem("PID (hex)")) {
							char buf[32];
							sprintf_s(buf, "0x%X", p->ProcessId);
							SetClipboardText(buf);
						}
						if (MenuItem("EPROCESS Address")) {
							char buf[32];
							sprintf_s(buf, "0x%016llX", p->EprocessAddress);
							SetClipboardText(buf);
						}
						if (_pdbHasDetailedFields) {
							Separator();
							if (p->TokenAddress && MenuItem("Token Address")) {
								char buf[32];
								sprintf_s(buf, "0x%016llX", p->TokenAddress);
								SetClipboardText(buf);
							}
							if (p->PebAddress && MenuItem("PEB Address")) {
								char buf[32];
								sprintf_s(buf, "0x%016llX", p->PebAddress);
								SetClipboardText(buf);
							}
							if (p->DirectoryTableBase && MenuItem("DirBase (CR3)")) {
								char buf[32];
								sprintf_s(buf, "0x%016llX", p->DirectoryTableBase);
								SetClipboardText(buf);
							}
							if (p->ObjectTableAddress && MenuItem("Object Table")) {
								char buf[32];
								sprintf_s(buf, "0x%016llX", p->ObjectTableAddress);
								SetClipboardText(buf);
							}
						}
						ImGui::EndMenu();
					}
					Separator();
					if (MenuItem("Show Details")) {
						_selectedProcess = p;
					}
					if (_pdbOffsetsResolved && MenuItem("DKOM Cross-Check")) {
						if (!_crossCheckRunning)
							RunCrossCheck();
					}
					EndPopup();
				}

				if (TableSetColumnIndex(1))
					Text("%u (0x%X)", p->ProcessId, p->ProcessId);

				if (TableSetColumnIndex(2))
					Text("0x%016llX", p->EprocessAddress);

				if (TableSetColumnIndex(3))
					Text("%u", p->ParentProcessId);

				if (TableSetColumnIndex(4))
					Text("%u", p->SessionId);

				if (TableSetColumnIndex(5))
					Text("%u", p->ThreadCount);

				if (TableSetColumnIndex(6))
					Text("%u", p->HandleCount);

				if (TableSetColumnIndex(7)) {
					if (p->CreateTime != 0) {
						FILETIME ft;
						ft.dwLowDateTime = (DWORD)(p->CreateTime & 0xFFFFFFFF);
						ft.dwHighDateTime = (DWORD)(p->CreateTime >> 32);
						SYSTEMTIME st, localSt;
						if (FileTimeToSystemTime(&ft, &st) && SystemTimeToTzSpecificLocalTime(nullptr, &st, &localSt)) {
							Text("%02d/%02d/%04d %02d:%02d:%02d",
								localSt.wMonth, localSt.wDay, localSt.wYear,
								localSt.wHour, localSt.wMinute, localSt.wSecond);
						}
						else {
							Text("-");
						}
					}
					else {
						Text("-");
					}
				}

				if (TableSetColumnIndex(8)) {
					if (_pdbHasDetailedFields && p->Protection != 0) {
						Text("%s-%s",
							ProtectionTypeToString(p->ProtectionType),
							ProtectionSignerToString(p->ProtectionSigner));
					}
					else if (p->IsProtectedLight)
						Text("PPL");
					else if (p->IsProtected)
						Text("Protected");
					else
						Text("");
				}

				if (TableSetColumnIndex(9)) {
					if (p->IsWow64)
						Text("Yes");
					else
						Text("");
				}

				if (_pdbHasDetailedFields) {
					if (TableSetColumnIndex(10)) {
						if (p->TokenAddress)
							Text("0x%016llX", p->TokenAddress);
						else
							Text("-");
					}

					if (TableSetColumnIndex(11)) {
						if (p->PebAddress)
							Text("0x%016llX", p->PebAddress);
						else
							Text("-");
					}

					if (TableSetColumnIndex(12)) {
						if (p->DirectoryTableBase)
							Text("0x%016llX", p->DirectoryTableBase);
						else
							Text("-");
					}

					if (TableSetColumnIndex(13)) {
						if (p->SignatureLevel || p->SectionSignatureLevel)
							Text("0x%02X / 0x%02X", p->SignatureLevel, p->SectionSignatureLevel);
						else
							Text("-");
					}

					if (TableSetColumnIndex(14)) {
						if (p->Flags || p->Flags2)
							Text("0x%08X / 0x%08X", p->Flags, p->Flags2);
						else
							Text("-");
					}

					if (TableSetColumnIndex(15)) {
						if (p->ObjectTableAddress)
							Text("0x%016llX", p->ObjectTableAddress);
						else
							Text("-");
					}

					if (TableSetColumnIndex(16)) {
						if (p->MitigationFlags || p->MitigationFlags2)
							Text("0x%08X / 0x%08X", p->MitigationFlags, p->MitigationFlags2);
						else
							Text("-");
					}
				}

				if (isProtected || isWinTcb)
					PopStyleColor();
			}
		}

		EndTable();
	}
}

void ProcessObjectsView::RunCrossCheck() {
	_crossCheckRunning = true;
	_crossCheckEntries.clear();
	LoggerView::AddLog(LoggerView::UserModeLog, "DKOM Cross-Check: Starting async scan...");

	_crossCheckFuture = std::async(std::launch::async, []() {
		return RemoteClient::IsConnected() ? RemoteClient::CrossCheckProcesses() : DriverHelper::CrossCheckProcesses();
	});
}

void ProcessObjectsView::BuildCrossCheckPanel() {
	if (!_crossCheckRan || !_showCrossCheck)
		return;

	Separator();
	if (_crossCheckHeader.SuspiciousCount > 0) {
		TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f),
			"DKOM DETECTION: %u process(es) found in CID table but NOT in ActiveProcessLinks!",
			_crossCheckHeader.SuspiciousCount);
	}
	else {
		TextColored(ImVec4(0.0f, 1.0f, 0.4f, 1.0f),
			"Cross-Check Clean: All %u processes consistent across ActiveProcessLinks and CID table.",
			_crossCheckHeader.ActiveLinksCount);
	}

	Text("ActiveProcessLinks: %u | PspCidTable: %u | Total unique: %u",
		_crossCheckHeader.ActiveLinksCount, _crossCheckHeader.CidTableCount,
		_crossCheckHeader.TotalEntries);
	Separator();

	if (BeginTable("crossCheckTable", 4,
		ImGuiTableFlags_Sortable | ImGuiTableFlags_Resizable |
		ImGuiTableFlags_ScrollX | ImGuiTableFlags_ScrollY |
		ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders)) {

		TableSetupScrollFreeze(1, 1);
		TableSetupColumn("Image Name", ImGuiTableColumnFlags_NoHide);
		TableSetupColumn("PID");
		TableSetupColumn("EPROCESS");
		TableSetupColumn("Sources");
		TableHeadersRow();

		ImGuiListClipper clipper;
		clipper.Begin(static_cast<int>(_crossCheckEntries.size()));

		while (clipper.Step()) {
			for (int j = clipper.DisplayStart; j < clipper.DisplayEnd; j++) {
				auto& e = _crossCheckEntries[j];
				TableNextRow();

				bool isSuspicious = (e.Sources & PROCESS_SOURCE_CID_TABLE) &&
					!(e.Sources & PROCESS_SOURCE_ACTIVE_LINKS);
				bool isLinksOnly = (e.Sources & PROCESS_SOURCE_ACTIVE_LINKS) &&
					!(e.Sources & PROCESS_SOURCE_CID_TABLE);

				if (isSuspicious)
					TableSetBgColor(ImGuiTableBgTarget_RowBg0, IM_COL32(180, 0, 0, 80));
				else if (isLinksOnly)
					TableSetBgColor(ImGuiTableBgTarget_RowBg0, IM_COL32(180, 180, 0, 40));

				if (isSuspicious)
					PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.2f, 0.2f, 1.0f));

				TableSetColumnIndex(0);
				Text("%s", e.ImageName.c_str());

				if (TableSetColumnIndex(1))
					Text("%u (0x%X)", e.ProcessId, e.ProcessId);

				if (TableSetColumnIndex(2))
					Text("0x%016llX", e.EprocessAddress);

				if (TableSetColumnIndex(3)) {
					std::string sources;
					if (e.Sources & PROCESS_SOURCE_ACTIVE_LINKS) sources += "ActiveLinks ";
					if (e.Sources & PROCESS_SOURCE_CID_TABLE) sources += "CidTable ";
					if (isSuspicious) sources += "[HIDDEN]";
					Text("%s", sources.c_str());
				}

				if (isSuspicious)
					PopStyleColor();
			}
		}

		EndTable();
	}
}

void ProcessObjectsView::BuildDetailsPanel() {
	if (!_selectedProcess || !_pdbHasDetailedFields)
		return;

	auto& p = _selectedProcess;

	Separator();
	Text("Details: %s (PID %u)", p->ImageName.c_str(), p->ProcessId);
	Separator();

	if (BeginTable("procDetails", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingFixedFit)) {
		TableSetupColumn("Field", ImGuiTableColumnFlags_WidthFixed, 200.0f);
		TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);

		auto Row = [](const char* field, const char* fmt, ...) {
			TableNextRow();
			TableSetColumnIndex(0);
			TextUnformatted(field);
			TableSetColumnIndex(1);
			va_list args;
			va_start(args, fmt);
			TextV(fmt, args);
			va_end(args);
		};

		Row("EPROCESS Address", "0x%016llX", p->EprocessAddress);
		Row("Process ID", "%u (0x%X)", p->ProcessId, p->ProcessId);
		Row("Parent Process ID", "%u", p->ParentProcessId);
		Row("Session ID", "%u", p->SessionId);
		Row("Thread Count", "%u", p->ThreadCount);
		Row("Handle Count", "%u", p->HandleCount);
		Row("WoW64", "%s", p->IsWow64 ? "Yes" : "No");

		if (p->Protection != 0) {
			Row("Protection Level", "0x%02X", p->Protection);
			Row("Protection Type", "%s (%d)", ProtectionTypeToString(p->ProtectionType), p->ProtectionType);
			Row("Protection Signer", "%s (%d)", ProtectionSignerToString(p->ProtectionSigner), p->ProtectionSigner);
		}
		else {
			Row("Protection", "None");
		}

		if (p->TokenAddress)
			Row("Token", "0x%016llX", p->TokenAddress);
		if (p->PebAddress)
			Row("PEB", "0x%016llX", p->PebAddress);
		if (p->DirectoryTableBase)
			Row("DirectoryTableBase (CR3)", "0x%016llX", p->DirectoryTableBase);
		if (p->ObjectTableAddress)
			Row("ObjectTable", "0x%016llX", p->ObjectTableAddress);
		if (p->SignatureLevel)
			Row("SignatureLevel", "0x%02X", p->SignatureLevel);
		if (p->SectionSignatureLevel)
			Row("SectionSignatureLevel", "0x%02X", p->SectionSignatureLevel);
		if (p->Flags)
			Row("Flags", "0x%08X", p->Flags);
		if (p->Flags2)
			Row("Flags2", "0x%08X", p->Flags2);
		if (p->MitigationFlags)
			Row("MitigationFlags", "0x%08X", p->MitigationFlags);
		if (p->MitigationFlags2)
			Row("MitigationFlags2", "0x%08X", p->MitigationFlags2);

		// Decode some common flags
		if (p->Flags) {
			std::string flagStrs;
			if (p->Flags & 0x00000001) flagStrs += "CreateReported ";
			if (p->Flags & 0x00000002) flagStrs += "NoDebugInherit ";
			if (p->Flags & 0x00000004) flagStrs += "ProcessExiting ";
			if (p->Flags & 0x00000008) flagStrs += "ProcessDelete ";
			if (p->Flags & 0x00000800) flagStrs += "VmDeleted ";
			if (p->Flags & 0x00002000) flagStrs += "Break_On_Termination ";
			if (p->Flags & 0x00040000) flagStrs += "ProcessSelfDelete ";
			if (!flagStrs.empty())
				Row("Flags (decoded)", "%s", flagStrs.c_str());
		}

		// Decode mitigation flags
		if (p->MitigationFlags) {
			std::string mitStrs;
			if (p->MitigationFlags & 0x00000001) mitStrs += "ControlFlowGuard ";
			if (p->MitigationFlags & 0x00000002) mitStrs += "CFG_ExportSuppression ";
			if (p->MitigationFlags & 0x00000020) mitStrs += "DEP ";
			if (p->MitigationFlags & 0x00000100) mitStrs += "ASLR_ForceRelocate ";
			if (p->MitigationFlags & 0x00000200) mitStrs += "ASLR_BottomUp ";
			if (p->MitigationFlags & 0x00000400) mitStrs += "ASLR_HighEntropy ";
			if (p->MitigationFlags & 0x00001000) mitStrs += "DisallowStrippedImages ";
			if (p->MitigationFlags & 0x00100000) mitStrs += "DisableDynamicCode ";
			if (p->MitigationFlags & 0x01000000) mitStrs += "BlockNonMicrosoftBinaries ";
			if (!mitStrs.empty())
				Row("Mitigations (decoded)", "%s", mitStrs.c_str());
		}

		EndTable();
	}
}
