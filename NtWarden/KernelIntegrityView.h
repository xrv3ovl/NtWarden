#pragma once

#include "ViewBase.h"
#include <vector>
#include <string>

class KernelIntegrityView : public ViewBase {
public:
	KernelIntegrityView();
	void BuildWindow();
	void RefreshNow();

	void ScanKernelIntegrity();
	void BuildKernelIntegrityTable();

private:
	struct KernelIntegrityEntry {
		std::string FunctionName;
		unsigned long long Address{ 0 };
		unsigned char ExpectedBytes[8]{};
		unsigned char ActualBytes[8]{};
		bool IsPatched{ false };
	};
	std::vector<KernelIntegrityEntry> _kernelIntegrity;
	bool _scanned{ false };
};
