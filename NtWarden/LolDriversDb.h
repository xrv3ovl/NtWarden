#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <mutex>

// LOLDrivers.io database for BYOVD detection
// Downloads and caches the driver vulnerability database, providing
// lookups by SHA256 hash and driver filename.

namespace LolDriversDb {

	struct VulnDriverInfo {
		std::string Id;
		std::string DriverName;			// Primary filename from Tags
		std::vector<std::string> Tags;	// All known filenames
		std::vector<std::string> CVEs;
		std::string Category;
		std::string Description;
		std::string SHA256;				// Hash of the specific sample that matched
	};

	enum class LoadState {
		NotLoaded,
		Loading,
		Loaded,
		Failed
	};

	// Initialize the database (downloads from loldrivers.io or loads from cache)
	// This is async-safe - call from any thread. Returns true if loaded successfully.
	bool Load();

	// Force re-download from loldrivers.io (ignores cache)
	bool Refresh();

	// Current state
	LoadState GetState();
	const std::string& GetLastError();

	// Lookup by SHA256 hash (lowercase hex). Returns nullptr if not found.
	const VulnDriverInfo* LookupByHash(const std::string& sha256);

	// Lookup by driver filename (case-insensitive). Returns nullptr if not found.
	const VulnDriverInfo* LookupByName(const std::string& driverName);

	// Get total number of known vulnerable driver entries
	size_t GetEntryCount();

	// Get total number of unique SHA256 hashes in database
	size_t GetHashCount();
}
