#pragma once

#include "ViewBase.h"
#include <string>

class DseStatusView : public ViewBase {
public:
	DseStatusView();
	void BuildWindow();
	void RefreshNow();

	void ScanDseStatus();
	void BuildDsePanel();
	void DecodeDseInfo(unsigned long ciOptions, unsigned long secureBootReg, unsigned long vbsReg);

private:
	struct DseInfo {
		bool DseEnabled{ true };
		bool TestSigningEnabled{ false };
		bool SecureBootEnabled{ false };
		bool HvciEnabled{ false };
		bool VbsEnabled{ false };
		unsigned long CodeIntegrityOptions{ 0 };
		bool Scanned{ false };
	};
	DseInfo _dseInfo;
};
