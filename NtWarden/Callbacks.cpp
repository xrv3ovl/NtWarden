#include "imgui.h"
#include "ImGuiExt.h"
#include "DriverHelper.h"
#include "RemoteClient.h"
#include "Callbacks.h"
#include "../KWinSys/KWinSysPublic.h"
#include "LoggerView.h"
#include "SymbolHelper.h"
#include <d3d11_1.h>
#include <stdio.h>
#include "SecurityHelper.h"
#include <Psapi.h>
#include <algorithm>

#pragma comment(lib, "psapi.lib")

MODULE_INFO obcallbacks_info[200] = { {0} };
static ImVector<int> selections[9];
const int MAX_BUF = 5000;
char cliptext[MAX_BUF];
bool get_callback_flag = true;
static bool g_callbacksSymbolsResolved = false;
static bool g_callbacksResolutionAttempted = false;
static std::string g_callbacksStatus = "Not resolved";
static CALLBACK_QUERY g_callbackQuery = {};

namespace {
	std::wstring NormalizeKernelImagePath(const std::wstring& path) {
		if (path.rfind(L"\\SystemRoot\\", 0) == 0) {
			wchar_t winDir[MAX_PATH]{};
			::GetWindowsDirectoryW(winDir, MAX_PATH);
			return std::wstring(winDir) + path.substr(11);
		}
		if (path.rfind(L"\\??\\", 0) == 0)
			return path.substr(4);
		return path;
	}

	bool ResolveCallbackQuery(CALLBACK_QUERY& query, std::string& status, bool useRemote = false) {
		query = {};

		DWORD64 moduleBase = 0;
		DWORD imageSize = 0;
		std::wstring pdbPath;
		wchar_t cacheDir[MAX_PATH]{};
		::GetCurrentDirectoryW(MAX_PATH, cacheDir);
		std::wstring symbolCacheDir = std::wstring(cacheDir) + L"\\Symbols";

		if (useRemote && RemoteClient::IsConnected()) {
			// Get kernel base info from the remote server
			KernelBaseInfoNet kbInfo{};
			if (!RemoteClient::GetKernelBase(kbInfo) || kbInfo.KernelBase == 0) {
				status = "Remote kernel base query failed";
				return false;
			}

			moduleBase = kbInfo.KernelBase;
			imageSize = kbInfo.ImageSize;

			GUID pdbGuid;
			memcpy(&pdbGuid, kbInfo.PdbGuid, sizeof(GUID));
			pdbPath = SymbolHelper::DownloadPdbBySignature(pdbGuid, kbInfo.PdbAge, kbInfo.PdbFileName, symbolCacheDir);
			if (pdbPath.empty()) {
				status = "PDB download failed (remote signature)";
				return false;
			}
		}
		else {
			// Local: use EnumDeviceDrivers
			LPVOID drivers[1024]{};
			DWORD cbNeeded = 0;
			if (!::EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) || cbNeeded < sizeof(LPVOID) || drivers[0] == nullptr) {
				status = "EnumDeviceDrivers failed";
				return false;
			}

			wchar_t driverPath[MAX_PATH]{};
			if (!::GetDeviceDriverFileNameW(drivers[0], driverPath, _countof(driverPath))) {
				status = "GetDeviceDriverFileName failed";
				return false;
			}

			auto fullPath = NormalizeKernelImagePath(driverPath);
			pdbPath = SymbolHelper::DownloadPdb(fullPath, symbolCacheDir);
			if (pdbPath.empty()) {
				status = "PDB download failed";
				return false;
			}

			{
				HANDLE hFile = ::CreateFileW(fullPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
				if (hFile == INVALID_HANDLE_VALUE)
					return false;
				HANDLE hMapping = ::CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
				if (!hMapping) {
					::CloseHandle(hFile);
					return false;
				}
				auto* base = static_cast<BYTE*>(::MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0));
				if (!base) {
					::CloseHandle(hMapping);
					::CloseHandle(hFile);
					return false;
				}
				auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
				if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
					auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
					imageSize = nt->OptionalHeader.SizeOfImage;
				}
				::UnmapViewOfFile(base);
				::CloseHandle(hMapping);
				::CloseHandle(hFile);
			}

			moduleBase = reinterpret_cast<DWORD64>(drivers[0]);
		}

		SymbolHelper symbols;
		if (!symbols.IsInitialized()) {
			status = "Symbol engine init failed";
			return false;
		}

		if (!symbols.LoadSymbolsFromPdb(pdbPath, L"ntoskrnl.exe", moduleBase, imageSize)) {
			status = "Symbols loaded, but callback types/symbols were not usable";
			return false;
		}

		query.ProcessNotifyArray = symbols.GetSymbolAddressFromName(moduleBase, L"PspCreateProcessNotifyRoutine");
		query.ThreadNotifyArray = symbols.GetSymbolAddressFromName(moduleBase, L"PspCreateThreadNotifyRoutine");
		query.ImageNotifyArray = symbols.GetSymbolAddressFromName(moduleBase, L"PspLoadImageNotifyRoutine");
		query.RegistryCallbackListHead = symbols.GetSymbolAddressFromName(moduleBase, L"CallbackListHead");
		query.ObjectTypeCallbackListOffset = symbols.GetStructMemberOffset(moduleBase, L"_OBJECT_TYPE", L"CallbackList");

		char text[256]{};
		sprintf_s(text,
			"Resolved symbols: Proc=0x%llX Thread=0x%llX Image=0x%llX Reg=0x%llX ObjOff=0x%X",
			query.ProcessNotifyArray, query.ThreadNotifyArray, query.ImageNotifyArray,
			query.RegistryCallbackListHead, query.ObjectTypeCallbackListOffset);
		status = text;
	LoggerView::AddLog(LoggerView::UserModeLog, "%s", status.c_str());
		if (query.ObjectTypeCallbackListOffset == 0 || query.ObjectTypeCallbackListOffset == (ULONG)-1) {
			LoggerView::AddLog(
		LoggerView::UserModeLog,
				"Callbacks: public symbols did not expose _OBJECT_TYPE.CallbackList; driver runtime/Vergilius fallback will be used if available");
		}
		return query.ProcessNotifyArray || query.ThreadNotifyArray || query.ImageNotifyArray ||
			query.RegistryCallbackListHead || query.ObjectTypeCallbackListOffset != 0;
	}
}

void Callbacks::Refresh() {
	get_callback_flag = true;
}

void clearSelectionsExcept(int selectionID) {
	for (size_t i = 0; i < 9; i++)
	{
		if (i != selectionID) {
			//gui::AddLog("Clearing selection id : %d", i);
			selections[i].clear();
		}
	}
}

void RenderTable(const char* table_name, int num_rows, MODULE_INFO obcallbacks_info[200], int table_type)
{
	const float TEXT_BASE_HEIGHT = ImGui::GetTextLineHeightWithSpacing();
	ImGuiTableColumnFlags column_flags = ImGuiTableColumnFlags_WidthFixed;
	ImVec2 outer_size = ImVec2(0.0f, TEXT_BASE_HEIGHT * num_rows);
	bool displayOp = table_type == 5 || table_type == 6 || table_type == 7 || table_type == 8;
	int length = 0;

	if (ImGui::BeginTable(table_name, 4, Callbacks::table_flags, outer_size))
	{
		ImGui::TableSetupScrollFreeze(0, 1); // Make top row always visible
		//ImGui::TableSetColumnEnabled(3, displayOp);
		ImGui::TableSetupColumn("ID", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoHide);
		ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed);
		ImGui::TableSetupColumn("Driver", ImGuiTableColumnFlags_WidthFixed);
		if (displayOp == false)
			column_flags |= ImGuiTableColumnFlags_Disabled;
		ImGui::TableSetupColumn("Operations", column_flags);


		ImGui::TableHeadersRow();
		int j = 0;
		int select_id = table_type - 1;

		for (int i = 0; i < 200; i++)
		{
			MODULE_INFO myob = obcallbacks_info[i];
			if (myob.type == table_type && myob.addr != 0 && myob.name != NULL) {
				char label[32];
				char label2[50];
				char opstr[100];

				sprintf_s(label, sizeof(label), "%02d", i);
				sprintf_s(label2, sizeof(label2), "%02d", j);
				ImGui::TableNextRow();
				if (ImGui::TableSetColumnIndex(0)) {
					const bool item_is_selected = selections[select_id].contains(i);
					ImGuiSelectableFlags selectable_flags = ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowItemOverlap;
					ImGui::PushID(label);
					if (ImGui::Selectable("", item_is_selected, selectable_flags))
					{
						clearSelectionsExcept(select_id);
						//selection2.clear(); selection3.clear();

						if (ImGui::GetIO().KeyCtrl)
						{
							if (item_is_selected)
								selections[select_id].find_erase_unsorted(i);
							else
								selections[select_id].push_back(i);
						}
						else
						{
							selections[select_id].clear();
							selections[select_id].push_back(i);
						}
					}
					ImGui::PopID();
					ImGui::SameLine();
					ImGui::Text("%s", label2);
				}
				if (ImGui::TableSetColumnIndex(1)) {
					ImGui::Text("0x%llx", myob.addr);
				}
				if (ImGui::TableSetColumnIndex(2)) {
					ImGui::Text("%s", myob.name);
				}

				if (ImGui::TableSetColumnIndex(3)) {
					opstr[0] = '\0';
					ULONG op = myob.operations;
					if (op & OB_OPERATION_HANDLE_CREATE)
						sprintf_s(opstr, sizeof(opstr), "CreateHandle");
					if (op & OB_OPERATION_HANDLE_DUPLICATE) {
						size_t len = strlen(opstr);
						sprintf_s(opstr + len, sizeof(opstr) - len, "%sDuplicateHandle", len > 0 ? "," : "");
					}
					ImGui::Text("%s", opstr);
				}

				if (!selections[select_id].empty() && ImGui::IsKeyDown(ImGuiKey_LeftCtrl) && ImGui::IsKeyDown(ImGuiKey_A)) {
					selections[select_id].push_back(i);
				}

				if (ImGui::IsKeyDown(ImGuiKey_LeftCtrl) && ImGui::IsKeyDown(ImGuiKey_C))
				{
					if (!selections[select_id].empty() && selections[select_id].contains(i)) {
						length += snprintf(cliptext + length, MAX_BUF - length, "%s | 0x%llx | %s | %s\n", label2, myob.addr, myob.name, displayOp ? opstr : "");
						ImGui::SetClipboardText(cliptext);
					}
				}
				j++;
			}
		}
		ImGui::EndTable();
	}
}

bool checkTypeExists(int type_to_find) {
	for (size_t i = 0; i < 200; i++)
	{
		if (obcallbacks_info[i].type == type_to_find)
			return true;
	}
	return false;
}

int GetTypeCount(int type_to_find) {
	int g = 0;
	for (size_t i = 0; i < 200; i++)
	{
		if (obcallbacks_info[i].type == type_to_find)
			g++;
	}
	return g;
}

void RenderTableShortWrapper(const char* table_name, int table_type) {
	int type_count = GetTypeCount(table_type);
	if (type_count > 0) {
		if (type_count > 8)
			RenderTable(table_name, 8, obcallbacks_info, table_type);
		else
			RenderTable(table_name, type_count + 2, obcallbacks_info, table_type);
	}
}


void Callbacks::RenderCallbackTables()
{
	if (get_callback_flag)
	{
		if (RemoteClient::IsConnected()) {
			if (!g_callbacksResolutionAttempted || !g_callbacksSymbolsResolved) {
				g_callbacksResolutionAttempted = true;
				g_callbacksSymbolsResolved = ResolveCallbackQuery(g_callbackQuery, g_callbacksStatus, true);
	LoggerView::AddLog(LoggerView::UserModeLog, "Callbacks (remote): %s", g_callbacksStatus.c_str());
			}

			MODULE_INFO* callbacks_temp = g_callbacksSymbolsResolved ? RemoteClient::GetCallbacks(g_callbackQuery) : nullptr;
			for (size_t i = 0; i < 200; i++)
				obcallbacks_info[i] = callbacks_temp ? callbacks_temp[i] : MODULE_INFO{};
		}
		else if (!DriverHelper::IsDriverLoaded()) {
	LoggerView::AddLog(LoggerView::UserModeLog, "Kernel driver not loaded. Some functionality will not be available.");
		}
		else {
			if (!g_callbacksResolutionAttempted || !g_callbacksSymbolsResolved) {
				g_callbacksResolutionAttempted = true;
				g_callbacksSymbolsResolved = ResolveCallbackQuery(g_callbackQuery, g_callbacksStatus);
	LoggerView::AddLog(LoggerView::UserModeLog, "Callbacks: %s", g_callbacksStatus.c_str());
			}

			MODULE_INFO* callbacks_temp = g_callbacksSymbolsResolved ? DriverHelper::GetCallbacks(g_callbackQuery) : nullptr;
			for (size_t i = 0; i < 200; i++)
			{
				obcallbacks_info[i] = callbacks_temp ? callbacks_temp[i] : MODULE_INFO{};
			}
		}
		get_callback_flag = false;
	}

	ImGui::Text("Callbacks");
	ImGui::SameLine();
	ImGui::TextDisabled("| %s", g_callbacksStatus.c_str());
	if (ImGui::BeginChild("CallbacksTableView")) {

		ImGui::SetNextItemOpen(1, ImGuiCond_Once);
		if (ImGui::CollapsingHeader("Process Callbacks (PspCreateProcessNotifyRoutine)")) {
			RenderTableShortWrapper("ProcCallbacksTable", 1);
		}

		ImGui::NewLine();

		ImGui::SetNextItemOpen(1, ImGuiCond_Once);
		if (ImGui::CollapsingHeader("Thread Callbacks (PspCreateThreadNotifyRoutine)")) {
			RenderTableShortWrapper("ThreadCallbacksTable", 2);
		}

		ImGui::NewLine();

		ImGui::SetNextItemOpen(1, ImGuiCond_Once);
		if (ImGui::CollapsingHeader("Image Callbacks (PspLoadImageNotifyRoutine)")) {
			RenderTableShortWrapper("ImageCallbacksTable", 3);
		}

		ImGui::NewLine();

		ImGui::SetNextItemOpen(1, ImGuiCond_Once);
		if (ImGui::CollapsingHeader("Registry Callbacks (CallbackListHead)")) {
			RenderTableShortWrapper("RegCallbacksTable", 4);
		}

		ImGui::NewLine();

		ImGui::SetNextItemOpen(1, ImGuiCond_Once);
		if (ImGui::CollapsingHeader("Process Object Callbacks (OBJECT_TYPE.CallbackList)")) {
			ImGui::SetNextItemOpen(1, ImGuiCond_Once);
			if (ImGui::TreeNode("PreObCallbacks")) {
				RenderTableShortWrapper("PreObCallbacksTable", 5);
				ImGui::TreePop();
			}
			ImGui::SetNextItemOpen(1, ImGuiCond_Once);
			if (ImGui::TreeNode("PostObCallbacks")) {
				RenderTableShortWrapper("PostObCallbacksTable", 6);
				ImGui::TreePop();
			}
		}

		ImGui::NewLine();

		ImGui::SetNextItemOpen(1, ImGuiCond_Once);
		if (ImGui::CollapsingHeader("Thread Object Callbacks (OBJECT_TYPE.CallbackList)")) {
			ImGui::SetNextItemOpen(1, ImGuiCond_Once);
			if (ImGui::TreeNode("PreObCallbacks##Thread")) {
				RenderTableShortWrapper("ThreadPreObCallbacksTable", 7);
				ImGui::TreePop();
			}
			ImGui::SetNextItemOpen(1, ImGuiCond_Once);
			if (ImGui::TreeNode("PostObCallbacks##Thread")) {
				RenderTableShortWrapper("ThreadPostObCallbacksTable", 8);
				ImGui::TreePop();
			}
		}
		ImGui::EndChild();
	}
}

/* =============== Callback Integrity Analysis =============== */

namespace {
	const char* CbTypeToString(int type) {
		switch (type) {
		case 0: return "Process Create";
		case 1: return "Process Terminate";
		case 2: return "Thread Create";
		case 3: return "Thread Terminate";
		case 4: return "Image Load";
		case 5: return "Registry";
		case 6: return "Object (Pre)";
		case 7: return "Object (Post)";
		default: return "Unknown";
		}
	}
}

static std::vector<Callbacks::IntegrityEntry> g_integrityEntries;

bool Callbacks::IsKnownEdrDriver(const std::string& name) {
	static const char* edrDrivers[] = {
		"wdfilter",
		"mbamswissarmy",
		"aswsp",
		"klif",
		"epfw",
		"sentinelmonitor",
		"crowdstrike", "csagent",
		"cbdefense",
		"tmfilter",
		"fltmgr",
		"ehdrv",
		"huntressagent",
		"sophosed",
		"cylancesvc",
		"pgpwded",
		"sysmon",
		"eamonm",
		"ekrn",
		"bdselfpr",
		"avfwot",
		"klhk",
		"klflt",
	};
	std::string lower = name;
	std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
	for (auto& edr : edrDrivers) {
		if (lower.find(edr) != std::string::npos)
			return true;
	}
	return false;
}

void Callbacks::ScanIntegrity() {
	g_integrityEntries.clear();

	if (RemoteClient::IsConnected()) {
		auto callbacks = RemoteClient::GetCallbacks(g_callbackQuery);
		for (int i = 0; i < 200 && callbacks[i].addr != 0; i++) {
			IntegrityEntry entry;
			entry.DriverName = callbacks[i].name;
			entry.Address = callbacks[i].addr;
			entry.CallbackType = callbacks[i].type;
			entry.IsKnownEdr = IsKnownEdrDriver(entry.DriverName);
			if (entry.IsKnownEdr)
				entry.Details = "Known EDR/AV driver";
			else if (entry.DriverName.empty() || entry.DriverName == "(unknown)")
				entry.IsSuspicious = true, entry.Details = "Unknown driver - possible callback injection";
			g_integrityEntries.push_back(std::move(entry));
		}
		return;
	}

	auto* callbacks = DriverHelper::GetCallbacks(g_callbackQuery);
	if (!callbacks) return;

	for (int i = 0; i < 200 && callbacks[i].addr != 0; i++) {
		IntegrityEntry entry;
		entry.DriverName = callbacks[i].name;
		entry.Address = callbacks[i].addr;
		entry.CallbackType = callbacks[i].type;
		entry.IsKnownEdr = IsKnownEdrDriver(entry.DriverName);

		if (entry.IsKnownEdr)
			entry.Details = "Known EDR/AV driver";
		else if (entry.DriverName.empty() || entry.DriverName[0] == '\0')
			entry.IsSuspicious = true, entry.Details = "Unresolved owner - possible rootkit";
		else
			entry.Details = "Third-party driver";

		g_integrityEntries.push_back(std::move(entry));
	}

	LoggerView::AddLog(LoggerView::UserModeLog, "Callback integrity check: %zu callbacks, %zu known EDR",
		g_integrityEntries.size(),
		std::count_if(g_integrityEntries.begin(), g_integrityEntries.end(), [](auto& e) { return e.IsKnownEdr; }));
}

void Callbacks::RenderIntegrityTable() {
	static bool scanned = false;
	if (!scanned) {
		ScanIntegrity();
		scanned = true;
	}

	int edrCount = 0, suspCount = 0;
	for (auto& e : g_integrityEntries) {
		if (e.IsKnownEdr) edrCount++;
		if (e.IsSuspicious) suspCount++;
	}

	if (!g_integrityEntries.empty()) {
		ImGui::Text("Callbacks: %zu total, %d EDR, %d suspicious", g_integrityEntries.size(), edrCount, suspCount);
		if (suspCount > 0)
			ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "Suspicious callbacks detected - possible injection or rootkit!");
	}

	if (ImGui::BeginTable("cbIntegrityTable", 5, ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_Sortable)) {
		ImGui::TableSetupScrollFreeze(1, 1);
		ImGui::TableSetupColumn("Driver");
		ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 140.0f);
		ImGui::TableSetupColumn("Type");
		ImGui::TableSetupColumn("EDR?", ImGuiTableColumnFlags_WidthFixed, 50.0f);
		ImGui::TableSetupColumn("Details");
		ImGui::TableHeadersRow();

		for (const auto& entry : g_integrityEntries) {
			ImGui::TableNextRow();
			if (entry.IsSuspicious) ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, IM_COL32(180, 40, 40, 60));
			else if (entry.IsKnownEdr) ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, IM_COL32(40, 100, 180, 40));
			ImGui::TableSetColumnIndex(0); ImGui::Text("%s", entry.DriverName.c_str());
			ImGui::TableSetColumnIndex(1); ImGui::Text("0x%llX", entry.Address);
			ImGui::TableSetColumnIndex(2); ImGui::Text("%s", CbTypeToString(entry.CallbackType));
			ImGui::TableSetColumnIndex(3);
			if (entry.IsKnownEdr) ImGui::TextColored(ImVec4(0.3f, 0.7f, 1.0f, 1.0f), "Yes");
			else ImGui::Text("No");
			ImGui::TableSetColumnIndex(4); ImGui::Text("%s", entry.Details.c_str());
		}
		ImGui::EndTable();
	}
}

