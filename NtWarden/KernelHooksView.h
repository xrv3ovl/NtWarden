#pragma once

#include <string>
#include <vector>
#include <future>

class KernelHooksView {
public:
	void BuildWindow();
	void RefreshNow();

private:
	struct HookEntry {
		unsigned long Id{ 0 };
		std::string Name;
		unsigned long long Address{ 0 };
		std::string Owner;
		std::string Reason;
		bool Suspicious{ false };
	};

	struct ScanResult {
		std::vector<HookEntry> entries;
		int suspiciousCount{ 0 };
	};

	void Refresh();
	static ScanResult RefreshAsync();

	bool _loaded{ false };
	bool _loading{ false };
	bool _loadFailed{ false };
	std::vector<HookEntry> _entries;
	int _suspiciousCount{ 0 };
	std::future<ScanResult> _scanFuture;
};
