#pragma once

#include "ViewBase.h"
#include <vector>

class RootCertificatesView : public ViewBase {
public:
	struct CertificateInfo {
		std::wstring Subject;
		std::wstring Issuer;
		std::wstring Thumbprint;
		std::wstring Store;
		std::wstring Expires;
	};

	RootCertificatesView();

	void BuildWindow();
	void RefreshNow();

private:
	void Refresh();
	void BuildToolBar();
	void BuildTable();

private:
	std::vector<CertificateInfo> _certificates;
};
