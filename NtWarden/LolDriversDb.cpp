#include "pch.h"
#include "LolDriversDb.h"
#include "LoggerView.h"
#include <nlohmann/json.hpp>
#include <winhttp.h>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <filesystem>
#include <ShlObj.h>

#pragma comment(lib, "Winhttp.lib")

using json = nlohmann::json;

namespace LolDriversDb {

	// ---- Internal state ----
	static std::mutex s_mutex;
	static LoadState s_state = LoadState::NotLoaded;
	static std::string s_lastError;

	// SHA256 (lowercase) -> VulnDriverInfo
	static std::unordered_map<std::string, VulnDriverInfo> s_hashMap;

	// Lowercase driver name -> list of VulnDriverInfo pointers (into s_entries)
	static std::unordered_map<std::string, std::vector<const VulnDriverInfo*>> s_nameMap;

	// Master list of all entries (one per driver ID, may have multiple hashes)
	static std::vector<VulnDriverInfo> s_entries;

	// ---- Helpers ----

	static std::string ToLower(const std::string& s) {
		std::string out = s;
		std::transform(out.begin(), out.end(), out.begin(), ::tolower);
		return out;
	}

	static std::wstring GetCachePath() {
		WCHAR appData[MAX_PATH]{};
		if (SUCCEEDED(::SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, appData))) {
			std::wstring dir = std::wstring(appData) + L"\\NtWarden";
			::CreateDirectoryW(dir.c_str(), nullptr);
			return dir + L"\\loldrivers.json";
		}
		return L"loldrivers.json";
	}

	static bool IsCacheFresh(const std::wstring& path) {
		WIN32_FILE_ATTRIBUTE_DATA fad{};
		if (!::GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fad))
			return false;

		FILETIME now{};
		::GetSystemTimeAsFileTime(&now);

		// Cache valid for 24 hours (in 100ns intervals)
		ULARGE_INTEGER uNow, uFile;
		uNow.LowPart = now.dwLowDateTime;
		uNow.HighPart = now.dwHighDateTime;
		uFile.LowPart = fad.ftLastWriteTime.dwLowDateTime;
		uFile.HighPart = fad.ftLastWriteTime.dwHighDateTime;

		constexpr ULONGLONG ONE_DAY = 10000000ULL * 60 * 60 * 24;
		return (uNow.QuadPart - uFile.QuadPart) < ONE_DAY;
	}

	// Download JSON from loldrivers.io using WinHTTP
	static std::string DownloadJson() {
		std::string result;

		HINTERNET hSession = ::WinHttpOpen(
			L"NtWarden/1.0",
			WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
			WINHTTP_NO_PROXY_NAME,
			WINHTTP_NO_PROXY_BYPASS, 0);
		if (!hSession) return result;

		HINTERNET hConnect = ::WinHttpConnect(hSession,
			L"www.loldrivers.io", INTERNET_DEFAULT_HTTPS_PORT, 0);
		if (!hConnect) { ::WinHttpCloseHandle(hSession); return result; }

		HINTERNET hRequest = ::WinHttpOpenRequest(hConnect,
			L"GET", L"/api/drivers.json",
			nullptr, WINHTTP_NO_REFERER,
			WINHTTP_DEFAULT_ACCEPT_TYPES,
			WINHTTP_FLAG_SECURE);
		if (!hRequest) {
			::WinHttpCloseHandle(hConnect);
			::WinHttpCloseHandle(hSession);
			return result;
		}

		// Set timeouts: 30s connect, 60s send/receive
		::WinHttpSetTimeouts(hRequest, 5000, 30000, 60000, 60000);

		if (::WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
			WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
			::WinHttpReceiveResponse(hRequest, nullptr)) {

			DWORD statusCode = 0;
			DWORD statusSize = sizeof(statusCode);
			::WinHttpQueryHeaders(hRequest,
				WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
				WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize,
				WINHTTP_NO_HEADER_INDEX);

			if (statusCode == 200) {
				DWORD bytesAvailable = 0;
				while (::WinHttpQueryDataAvailable(hRequest, &bytesAvailable) && bytesAvailable > 0) {
					std::vector<char> buf(bytesAvailable);
					DWORD bytesRead = 0;
					if (::WinHttpReadData(hRequest, buf.data(), bytesAvailable, &bytesRead))
						result.append(buf.data(), bytesRead);
				}
			}
		}

		::WinHttpCloseHandle(hRequest);
		::WinHttpCloseHandle(hConnect);
		::WinHttpCloseHandle(hSession);
		return result;
	}

	static bool ParseAndBuild(const std::string& jsonStr) {
		try {
			auto root = json::parse(jsonStr);
			if (!root.is_array()) {
				s_lastError = "JSON root is not an array";
				return false;
			}

			std::vector<VulnDriverInfo> entries;
			std::unordered_map<std::string, VulnDriverInfo> hashMap;
			std::unordered_map<std::string, std::vector<size_t>> nameIndexMap;

			for (auto& drv : root) {
				VulnDriverInfo base;

				// Id
				if (drv.contains("Id") && drv["Id"].is_string())
					base.Id = drv["Id"].get<std::string>();

				// Tags -> driver filenames
				if (drv.contains("Tags") && drv["Tags"].is_array()) {
					for (auto& tag : drv["Tags"]) {
						if (tag.is_string())
							base.Tags.push_back(tag.get<std::string>());
					}
					if (!base.Tags.empty())
						base.DriverName = base.Tags[0];
				}

				// Category
				if (drv.contains("Category") && drv["Category"].is_string())
					base.Category = drv["Category"].get<std::string>();

				// CVEs - can be absent or null
				if (drv.contains("CVE") && drv["CVE"].is_array()) {
					for (auto& c : drv["CVE"]) {
						if (c.is_string()) {
							auto cveStr = c.get<std::string>();
							if (!cveStr.empty())
								base.CVEs.push_back(cveStr);
						}
					}
				}

				// Description from Commands
				if (drv.contains("Commands") && drv["Commands"].is_object()) {
					auto& cmds = drv["Commands"];
					if (cmds.contains("Description") && cmds["Description"].is_string())
						base.Description = cmds["Description"].get<std::string>();
				}

				// KnownVulnerableSamples - each has SHA256, MD5, etc.
				if (drv.contains("KnownVulnerableSamples") && drv["KnownVulnerableSamples"].is_array()) {
					for (auto& sample : drv["KnownVulnerableSamples"]) {
						std::string sha256;
						if (sample.contains("SHA256") && sample["SHA256"].is_string())
							sha256 = ToLower(sample["SHA256"].get<std::string>());

						if (!sha256.empty() && sha256.size() == 64) {
							VulnDriverInfo entry = base;
							entry.SHA256 = sha256;

							// Use sample-specific filename if available
							if (sample.contains("Filename") && sample["Filename"].is_string()) {
								auto fn = sample["Filename"].get<std::string>();
								if (!fn.empty())
									entry.DriverName = fn;
							}

							size_t idx = entries.size();
							hashMap[sha256] = entry;
							entries.push_back(std::move(entry));

							// Index by all tag names
							for (auto& tag : base.Tags) {
								nameIndexMap[ToLower(tag)].push_back(idx);
							}
						}
					}
				}

				// Also index entries with no samples (name-only match)
				if (!drv.contains("KnownVulnerableSamples") ||
					!drv["KnownVulnerableSamples"].is_array() ||
					drv["KnownVulnerableSamples"].empty()) {
					size_t idx = entries.size();
					entries.push_back(base);
					for (auto& tag : base.Tags) {
						nameIndexMap[ToLower(tag)].push_back(idx);
					}
				}
			}

			// Build the name->pointer map after entries are stable
			std::unordered_map<std::string, std::vector<const VulnDriverInfo*>> nameMap;

			// Commit to global state
			{
				std::lock_guard<std::mutex> lk(s_mutex);
				s_entries = std::move(entries);
				s_hashMap = std::move(hashMap);

				// Rebuild name map with stable pointers
				for (auto& [name, indices] : nameIndexMap) {
					auto& vec = nameMap[name];
					for (auto idx : indices) {
						if (idx < s_entries.size())
							vec.push_back(&s_entries[idx]);
					}
				}
				s_nameMap = std::move(nameMap);
			}

			return true;

		}
		catch (const std::exception& ex) {
			s_lastError = std::string("JSON parse error: ") + ex.what();
			return false;
		}
	}

	static bool LoadFromCacheOrDownload(bool forceDownload) {
		auto cachePath = GetCachePath();
		std::string jsonStr;

		// Try cache first (unless force download)
		if (!forceDownload && IsCacheFresh(cachePath)) {
			std::ifstream ifs(cachePath, std::ios::binary);
			if (ifs.good()) {
				std::ostringstream oss;
				oss << ifs.rdbuf();
				jsonStr = oss.str();
				if (!jsonStr.empty()) {
	LoggerView::AddLog(LoggerView::UserModeLog,
						"LOLDrivers: Loading from cache (%zu bytes)", jsonStr.size());
				}
			}
		}

		// Download if cache miss
		if (jsonStr.empty()) {
	LoggerView::AddLog(LoggerView::UserModeLog,
				"LOLDrivers: Downloading from loldrivers.io...");
			jsonStr = DownloadJson();
			if (jsonStr.empty()) {
				s_lastError = "Failed to download LOLDrivers database";
				return false;
			}

	LoggerView::AddLog(LoggerView::UserModeLog,
				"LOLDrivers: Downloaded %zu bytes", jsonStr.size());

			// Save to cache
			std::ofstream ofs(cachePath, std::ios::binary);
			if (ofs.good())
				ofs.write(jsonStr.data(), jsonStr.size());
		}

		if (!ParseAndBuild(jsonStr))
			return false;

	LoggerView::AddLog(LoggerView::UserModeLog,
			"LOLDrivers: Loaded %zu entries, %zu unique hashes",
			s_entries.size(), s_hashMap.size());

		return true;
	}

	// ---- Public API ----

	bool Load() {
		{
			std::lock_guard<std::mutex> lk(s_mutex);
			if (s_state == LoadState::Loaded) return true;
			if (s_state == LoadState::Loading) return false;
			s_state = LoadState::Loading;
		}

		bool ok = LoadFromCacheOrDownload(false);

		{
			std::lock_guard<std::mutex> lk(s_mutex);
			s_state = ok ? LoadState::Loaded : LoadState::Failed;
		}
		return ok;
	}

	bool Refresh() {
		{
			std::lock_guard<std::mutex> lk(s_mutex);
			s_state = LoadState::Loading;
		}

		bool ok = LoadFromCacheOrDownload(true);

		{
			std::lock_guard<std::mutex> lk(s_mutex);
			s_state = ok ? LoadState::Loaded : LoadState::Failed;
		}
		return ok;
	}

	LoadState GetState() {
		std::lock_guard<std::mutex> lk(s_mutex);
		return s_state;
	}

	const std::string& GetLastError() {
		std::lock_guard<std::mutex> lk(s_mutex);
		return s_lastError;
	}

	const VulnDriverInfo* LookupByHash(const std::string& sha256) {
		std::lock_guard<std::mutex> lk(s_mutex);
		auto it = s_hashMap.find(ToLower(sha256));
		if (it != s_hashMap.end())
			return &it->second;
		return nullptr;
	}

	const VulnDriverInfo* LookupByName(const std::string& driverName) {
		std::lock_guard<std::mutex> lk(s_mutex);
		auto it = s_nameMap.find(ToLower(driverName));
		if (it != s_nameMap.end() && !it->second.empty())
			return it->second[0]; // Return first match
		return nullptr;
	}

	size_t GetEntryCount() {
		std::lock_guard<std::mutex> lk(s_mutex);
		return s_entries.size();
	}

	size_t GetHashCount() {
		std::lock_guard<std::mutex> lk(s_mutex);
		return s_hashMap.size();
	}
}
