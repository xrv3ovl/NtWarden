#pragma once

#include "ViewBase.h"
#include <string>

class CiPolicyView : public ViewBase {
public:
	CiPolicyView();
	void BuildWindow();
	void RefreshNow();

	void ScanCiPolicy();
	void BuildCiPolicyPanel();

private:
	struct CiPolicyInfo {
		bool CodeIntegrityEnabled{ false };
		bool TestSignEnabled{ false };
		bool UmciEnabled{ false };
		bool HvciRunning{ false };
		bool DebugModeEnabled{ false };
		bool FlightSignedEnabled{ false };
		unsigned long CiOptions{ 0 };
		bool Scanned{ false };
	};
	CiPolicyInfo _ciPolicy;
};
