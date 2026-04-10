#pragma once

#include "ViewBase.h"
#include <vector>
#include <string>

class HypervisorHookView : public ViewBase {
public:
	HypervisorHookView();
	void BuildWindow();
	void RefreshNow();

	void ScanHypervisorHooks();
	void BuildHypervisorHookTable();

private:
	struct HypervisorHookEntry {
		std::string FunctionName;
		unsigned long long Address{ 0 };
		unsigned long long AvgCycles{ 0 };
		unsigned long long BaselineCycles{ 0 };
		bool TimingAnomaly{ false };
	};
	std::vector<HypervisorHookEntry> _hypervisorHooks;
};
