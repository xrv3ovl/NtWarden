#include "pch.h"
#include "imgui.h"
#include "ModulesView.h"
#include <algorithm>
#include "SortHelper.h"
#include "TabManager.h"
#include <shellapi.h>
#include "FormatHelper.h"
#include "ImGuiExt.h"
#include "Globals.h"
#include "RemoteClient.h"
#include "colors.h"
#include <WICTextureLoader.h>
#include <wincodec.h>
#include "resource.h"
#include "LoggerView.h"
#include "LolDriversDb.h"
#include <bcrypt.h>
#include <thread>

#pragma comment(lib,"Version.lib")
#pragma comment(lib,"Bcrypt.lib")

using namespace ImGui;

bool get_module_info = true;

ModulesView::ModulesView() : ViewBase(10000) {
}

void ModulesView::RefreshNow() {
	RefreshModules();
	MarkUpdated();
}

void ModulesView::RefreshModules() {
	unsigned long count = 0;
	_modules.clear();

	bool remote = RemoteClient::IsConnected();
	bool snapshotOk = remote ? RemoteClient::CreateModuleSnapshot(count) : DriverHelper::CreateModuleSnapshot(count);
	if (!snapshotOk)
		return;

	_modules.reserve(count);
	constexpr unsigned long pageSize = 64;
	std::vector<KERNEL_MODULE_ENTRY> page(pageSize);
	for (unsigned long start = 0; start < count; start += pageSize) {
		unsigned long returned = 0;
		auto requestCount = (std::min)(pageSize, count - start);
		bool pageOk = remote
			? RemoteClient::QueryModulePage(start, requestCount, page.data(), returned)
			: DriverHelper::QueryModulePage(start, requestCount, page.data(), returned);
		if (!pageOk)
			break;

		for (unsigned long i = 0; i < returned; i++) {
			auto row = std::make_shared<ModuleRow>();
			row->Name = page[i].Name;
			row->FullPath = page[i].FullPath;
			row->ImageBase = page[i].ImageBase;
			row->ImageSize = page[i].ImageSize;
			row->LoadOrderIndex = page[i].LoadOrderIndex;
			_modules.push_back(std::move(row));
		}
	}

	if (remote)
		RemoteClient::ReleaseModuleSnapshot();
	else
		DriverHelper::ReleaseModuleSnapshot();

	LoggerView::AddLog(LoggerView::UserModeLog, "Enumerated %zu kernel modules", _modules.size());
}

void ModulesView::BuildWindow()
{
	PollByovdResult();
	BuildToolBar();
	Separator();
	BuildTable();
}

void ModulesView::BuildToolBar()
{
	Separator();
	DrawFilterToolbar();

	SameLine();
	DrawUpdateIntervalToolbar("##ModuleUpdateInterval", false);

	// BYOVD controls
	SameLine();
	TextDisabled("|");
	SameLine();

	if (_byovdScanning) {
		TextColored(ImVec4(1.0f, 1.0f, 0.3f, 1.0f), "BYOVD scanning...");
	}
	else {
		if (Button("BYOVD Scan")) {
			if (_modules.empty())
				RefreshModules();
			RunByovdScan();
		}
		if (IsItemHovered()) {
			BeginTooltip();
			TextUnformatted("Hash all loaded drivers and check against LOLDrivers.io database");
			EndTooltip();
		}
	}

	SameLine();
	if (Button("Update LOLDrivers DB")) {
		std::thread([] { LolDriversDb::Refresh(); }).detach();
	LoggerView::AddLog(LoggerView::UserModeLog, "LOLDrivers: Refreshing database from loldrivers.io...");
	}

	SameLine();
	auto dbState = LolDriversDb::GetState();
	if (dbState == LolDriversDb::LoadState::Loaded) {
		TextDisabled("DB: %zu entries, %zu hashes",
			LolDriversDb::GetEntryCount(), LolDriversDb::GetHashCount());
	}
	else if (dbState == LolDriversDb::LoadState::Loading) {
		TextColored(ImVec4(1.0f, 1.0f, 0.3f, 1.0f), "Downloading LOLDrivers DB...");
	}
	else if (dbState == LolDriversDb::LoadState::Failed) {
		TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "DB failed");
		SameLine();
		if (SmallButton("Retry")) {
			std::thread([] { LolDriversDb::Refresh(); }).detach();
		}
	}

	// BYOVD summary banner
	if (_byovdScanned) {
		int vulnCount = 0, hashMatchCount = 0, nameMatchCount = 0;
		for (auto& m : _modules) {
			if (m->IsKnownVulnerable) {
				vulnCount++;
				if (m->HashMatch) hashMatchCount++;
				else nameMatchCount++;
			}
		}

		if (vulnCount > 0) {
			SameLine();
			TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f),
				"%d vulnerable driver(s)!", vulnCount);
			if (IsItemHovered()) {
				BeginTooltip();
				if (hashMatchCount > 0)
					TextColored(ImVec4(1.0f, 0.2f, 0.2f, 1.0f), "%d confirmed by SHA256 hash", hashMatchCount);
				if (nameMatchCount > 0)
					TextColored(ImVec4(1.0f, 0.6f, 0.0f, 1.0f), "%d matched by filename only (may be patched)", nameMatchCount);
				EndTooltip();
			}
		}
		else {
			SameLine();
			TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), "No vulnerable drivers");
		}
	}
}

std::wstring ModulesView::GetCompanyName(std::wstring path) {
	BYTE buffer[1 << 12];
	WCHAR* companyName = nullptr;
	CString filePath = path.c_str();
	if (filePath.Left(12).CompareNoCase(L"\\SystemRoot\\") == 0) {
		wchar_t winDir[MAX_PATH]{};
		::GetWindowsDirectoryW(winDir, _countof(winDir));
		filePath = CString(winDir) + filePath.Mid(11);
	}
	else if (filePath.Left(4) == L"\\??\\")
		filePath = filePath.Mid(4);
	if (::GetFileVersionInfo(filePath, 0, sizeof(buffer), buffer)) {
		WORD* langAndCodePage;
		UINT len;
		if (::VerQueryValue(buffer, L"\\VarFileInfo\\Translation", (void**)&langAndCodePage, &len)) {
			CString text;
			text.Format(L"\\StringFileInfo\\%04x%04x\\CompanyName", langAndCodePage[0], langAndCodePage[1]);

			if (::VerQueryValue(buffer, text, (void**)&companyName, &len))
				return companyName;
		}
	}
	return L"";
}

std::wstring StringToWstring(const std::string& str) {
	int len = MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, nullptr, 0);
	len += 1;
	std::unique_ptr<wchar_t[]> buffer = std::make_unique<wchar_t[]>(len);
	memset(buffer.get(), 0, sizeof(wchar_t) * len);
	MultiByteToWideChar(CP_ACP, 0, str.c_str(), static_cast<int>(str.size()), buffer.get(), len);
	std::wstring wstr(buffer.get());
	return wstr;
}

static std::string WstringToString(const std::wstring& str) {
	auto len = WideCharToMultiByte(CP_ACP, 0, str.c_str(), -1, nullptr, 0, nullptr, nullptr);
	if (len <= 1)
		return {};
	std::string result(len - 1, '\0');
	WideCharToMultiByte(CP_ACP, 0, str.c_str(), -1, result.data(), len, nullptr, nullptr);
	return result;
}

static std::wstring NormalizeDisplayPath(std::wstring path) {
	if (path.rfind(L"\\SystemRoot\\", 0) == 0) {
		wchar_t winDir[MAX_PATH]{};
		::GetWindowsDirectoryW(winDir, _countof(winDir));
		return std::wstring(winDir) + path.substr(11);
	}
	if (path.rfind(L"\\??\\", 0) == 0)
		return path.substr(4);
	return path;
}

static std::wstring NormalizeKernelPath(const std::string& fullPath) {
	std::wstring wPath;
	if (fullPath.find("\\SystemRoot\\") == 0) {
		WCHAR winDir[MAX_PATH]{};
		::GetWindowsDirectoryW(winDir, MAX_PATH);
		wPath = std::wstring(winDir) + L"\\" + std::wstring(fullPath.begin() + 12, fullPath.end());
	}
	else if (fullPath.find("\\??\\") == 0) {
		wPath.assign(fullPath.begin() + 4, fullPath.end());
	}
	else {
		wPath.assign(fullPath.begin(), fullPath.end());
	}
	return wPath;
}

static std::string ComputeSha256(const std::wstring& filePath) {
	HANDLE hFile = ::CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hFile == INVALID_HANDLE_VALUE) return "";

	BCRYPT_ALG_HANDLE hAlg = nullptr;
	BCRYPT_HASH_HANDLE hHash = nullptr;
	std::string result;

	if (BCRYPT_SUCCESS(::BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0))) {
		ULONG hashLen = 0, resultLen = 0;
		::BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLen, sizeof(hashLen), &resultLen, 0);

		if (BCRYPT_SUCCESS(::BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0))) {
			BYTE buffer[65536];
			DWORD bytesRead = 0;
			while (::ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, nullptr) && bytesRead > 0) {
				::BCryptHashData(hHash, buffer, bytesRead, 0);
			}

			std::vector<BYTE> hash(hashLen);
			if (BCRYPT_SUCCESS(::BCryptFinishHash(hHash, hash.data(), hashLen, 0))) {
				char hex[3];
				for (ULONG i = 0; i < hashLen; i++) {
					sprintf_s(hex, "%02x", hash[i]);
					result += hex;
				}
			}
			::BCryptDestroyHash(hHash);
		}
		::BCryptCloseAlgorithmProvider(hAlg, 0);
	}
	::CloseHandle(hFile);
	return result;
}

void ModulesView::RunByovdScan() {
	if (_byovdScanning) return;
	if (_modules.empty()) return;

	_byovdScanning = true;

	// Capture module names/paths for the async task
	struct ModuleInfo { std::string Name; std::string FullPath; };
	std::vector<ModuleInfo> moduleList;
	moduleList.reserve(_modules.size());
	for (auto& m : _modules)
		moduleList.push_back({ m->Name, m->FullPath });

	_byovdFuture = std::async(std::launch::async, [moduleList = std::move(moduleList)]() -> std::vector<ByovdResult> {
		std::vector<ByovdResult> results;

		// Load LOLDrivers database
		if (LolDriversDb::GetState() != LolDriversDb::LoadState::Loaded) {
			if (!LolDriversDb::Load()) {
	LoggerView::AddLog(LoggerView::UserModeLog,
					"BYOVD: Failed to load LOLDrivers DB: %s", LolDriversDb::GetLastError().c_str());
			}
		}

		bool dbLoaded = (LolDriversDb::GetState() == LolDriversDb::LoadState::Loaded);
		if (dbLoaded) {
	LoggerView::AddLog(LoggerView::UserModeLog,
				"BYOVD: LOLDrivers DB loaded - %zu entries, %zu hashes",
				LolDriversDb::GetEntryCount(), LolDriversDb::GetHashCount());
		}

		for (auto& mod : moduleList) {
			ByovdResult r;
			r.Name = mod.Name;

			auto wPath = NormalizeKernelPath(mod.FullPath);
			r.Hash = ComputeSha256(wPath);

			if (dbLoaded) {
				// Primary: SHA256 hash match
				if (!r.Hash.empty()) {
					auto* info = LolDriversDb::LookupByHash(r.Hash);
					if (info) {
						r.IsKnownVulnerable = true;
						r.HashMatch = true;
						r.LolDriverId = info->Id;
						r.Category = info->Category;
						r.Description = info->Description;
						if (!info->CVEs.empty()) {
							r.CveId = info->CVEs[0];
							for (size_t c = 1; c < info->CVEs.size(); c++)
								r.CveId += ", " + info->CVEs[c];
						}
					}
				}

				// Secondary: filename match
				if (!r.IsKnownVulnerable) {
					auto* info = LolDriversDb::LookupByName(mod.Name);
					if (info) {
						r.IsKnownVulnerable = true;
						r.HashMatch = false;
						r.LolDriverId = info->Id;
						r.Category = info->Category;
						r.Description = info->Description;
						if (!info->CVEs.empty()) {
							r.CveId = info->CVEs[0];
							for (size_t c = 1; c < info->CVEs.size(); c++)
								r.CveId += ", " + info->CVEs[c];
						}
					}
				}
			}

			results.push_back(std::move(r));
		}

		return results;
	});
}

void ModulesView::PollByovdResult() {
	if (_byovdScanning && _byovdFuture.valid() &&
		_byovdFuture.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
		auto results = _byovdFuture.get();
		_byovdScanning = false;
		_byovdScanned = true;

		// Enrich existing modules with BYOVD data by matching on name
		for (auto& r : results) {
			for (auto& m : _modules) {
				if (m->Name == r.Name) {
					m->Hash = r.Hash;
					m->IsKnownVulnerable = r.IsKnownVulnerable;
					m->HashMatch = r.HashMatch;
					m->CveId = r.CveId;
					m->Description = r.Description;
					m->Category = r.Category;
					m->LolDriverId = r.LolDriverId;
					break;
				}
			}
		}

		int vulnCount = 0;
		for (auto& m : _modules)
			if (m->IsKnownVulnerable) vulnCount++;

		if (vulnCount > 0)
	LoggerView::AddLog(LoggerView::UserModeLog, "BYOVD: %d known vulnerable driver(s) found!", vulnCount);
		else
	LoggerView::AddLog(LoggerView::UserModeLog, "BYOVD: No known vulnerable drivers found among %zu modules.", _modules.size());
	}
}

void ModulesView::BuildTable()
{
	if (BeginTable("modTable", 10, ImGuiTableFlags_BordersV * 0 | ImGuiTableFlags_Sortable |
		ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable | 0 * ImGuiTableFlags_NoSavedSettings | ImGuiTableFlags_ScrollX | ImGuiTableFlags_ScrollY |
		ImGuiTableFlags_RowBg | ImGuiTableFlags_Hideable | ImGuiTableFlags_NoSavedSettings
	)) {
		TableSetupScrollFreeze(1, 1);
		TableSetupColumn("Name", ImGuiTableColumnFlags_NoHide | ImGuiTableColumnFlags_NoReorder);
		TableSetupColumn("Image Base");
		TableSetupColumn("Image Size");
		TableSetupColumn("Load Order");
		TableSetupColumn("Company Name");
		TableSetupColumn("Full Path");
		TableSetupColumn("SHA256", ImGuiTableColumnFlags_DefaultHide);
		TableSetupColumn("CVE", ImGuiTableColumnFlags_DefaultHide);
		TableSetupColumn("Match", ImGuiTableColumnFlags_DefaultHide);
		TableSetupColumn("Status", ImGuiTableColumnFlags_DefaultHide);

		TableHeadersRow();

		if (IsUpdateDue()) {
			auto empty = _modules.empty();
			if (empty) {
				_modules.reserve(1024);
			}
			RefreshModules();
			//if (_specs)
			//	DoSort(_specs->ColumnIndex, _specs->SortDirection == ImGuiSortDirection_Ascending);
			MarkUpdated();
		}


		auto filter = GetFilterTextLower();
		std::vector<int> indices;
		indices.reserve(_modules.size());

		auto count = static_cast<int>(_modules.size());
		for (int i = 0; i < count; i++) {
			auto& m = _modules[i];
			m->Filtered = false;
			if (!filter.IsEmpty()) {
				CString name(m->Name.c_str());
				name.MakeLower();
				if (name.Find(filter) < 0) {
					m->Filtered = true;
					continue;
				}
			}
			indices.push_back(i);
		}

		//auto specs = TableGetSortSpecs();
		//if (specs && specs->SpecsDirty) {
		//	_specs = specs->Specs;
		//	DoSort(_specs->ColumnIndex, _specs->SortDirection == ImGuiSortDirection_Ascending);
		//	specs->SpecsDirty = false;
		//}

		USES_CONVERSION;
		ImGuiListClipper clipper;

		count = static_cast<int>(indices.size());
		clipper.Begin(count);

		static bool selected = false;
		CStringA str;
		static char buffer[64];
		int popCount = 3;
		auto special = false;

		while (clipper.Step()) {
			for (int j = clipper.DisplayStart; j < clipper.DisplayEnd; j++) {
				int i = indices[j];
				auto& s = _modules[i];
				if (s->Filtered) {
					clipper.ItemsCount--;
					continue;
				}
				TableNextRow();

				if (special)
					PopStyleColor(popCount);
				if (_selectedModule != nullptr)
				{
					special = s->Name == _selectedModule->Name;
					if (special)
					{
						const auto& color = GetStyle().Colors[ImGuiCol_TextSelectedBg];
						PushStyleColor(ImGuiCol_TableRowBg, color);
						PushStyleColor(ImGuiCol_TableRowBgAlt, color);
						PushStyleColor(ImGuiCol_Text, GetStyle().Colors[ImGuiCol_Text]);
					}
				}

				std::wstring path = NormalizeDisplayPath(StringToWstring(s->FullPath));
				CString corp_name = GetCompanyName(path).c_str();
				bool is_microsoft = !corp_name.Find(L"Microsoft");

				if (is_microsoft)
					ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.5019608f, 0.5019608f, 0.5019608f, 1));

				// BYOVD row coloring
				if (s->IsKnownVulnerable && s->HashMatch)
					TableSetBgColor(ImGuiTableBgTarget_RowBg0, IM_COL32(180, 40, 40, 60));
				else if (s->IsKnownVulnerable)
					TableSetBgColor(ImGuiTableBgTarget_RowBg0, IM_COL32(180, 100, 0, 50));

				TableSetColumnIndex(0);
				str.Format("%s##%d", s->Name.c_str(), i);
				Selectable(str, false, ImGuiSelectableFlags_SpanAllColumns);

				::StringCchPrintfA(buffer, sizeof(buffer), "##%d", i);

				if (IsItemClicked()) {
					LoggerView::AddLog(LoggerView::UserModeLog, str);
					_selectedModule = s;
				}

				if (TableSetColumnIndex(1)) {
				Text("0x%llx", s->ImageBase);
				}

				if (TableSetColumnIndex(2)) {
					Text("0x%x", s->ImageSize);
				}

				if (TableSetColumnIndex(3)) {
					Text("%u", s->LoadOrderIndex);
				}

				if (TableSetColumnIndex(4)) {
					Text("%ws", corp_name);
				}

				if (TableSetColumnIndex(5)) {
					auto displayPath = WstringToString(path);
					Text("%s", displayPath.c_str());
				}

				// BYOVD columns
				if (TableSetColumnIndex(6)) {
					if (!s->Hash.empty()) {
						std::string shortHash = s->Hash.substr(0, 16) + "...";
						Text("%s", shortHash.c_str());
						if (IsItemHovered()) {
							BeginTooltip();
							Text("SHA256: %s", s->Hash.c_str());
							if (s->HashMatch)
								TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "Hash matches LOLDrivers database!");
							EndTooltip();
						}
					}
					else if (_byovdScanned) {
						TextDisabled("-");
					}
				}

				if (TableSetColumnIndex(7)) {
					if (!s->CveId.empty())
						Text("%s", s->CveId.c_str());
					else if (s->IsKnownVulnerable)
						TextDisabled("N/A");
					else if (_byovdScanned)
						TextDisabled("-");
				}

				if (TableSetColumnIndex(8)) {
					if (s->IsKnownVulnerable) {
						if (s->HashMatch)
							TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "SHA256");
						else
							TextColored(ImVec4(1.0f, 0.6f, 0.0f, 1.0f), "Name");
					}
					else if (_byovdScanned) {
						TextDisabled("-");
					}
				}

				if (TableSetColumnIndex(9)) {
					if (s->IsKnownVulnerable && s->HashMatch)
						TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "VULNERABLE");
					else if (s->IsKnownVulnerable)
						TextColored(ImVec4(1.0f, 0.6f, 0.0f, 1.0f), "SUSPECT");
					else if (_byovdScanned)
						TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), "OK");
				}

				if (is_microsoft)
					ImGui::PopStyleColor();

			}
		}

		if (special) {
			PopStyleColor(popCount);
		}
		ImGui::EndTable();
	}
}
