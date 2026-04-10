#pragma once

#include "ViewBase.h"
#include <vector>

class NdisView : public ViewBase {
public:
	NdisView();

	void BuildWindow();
	void RefreshNow();

private:
	struct AdapterInfo {
		std::wstring FriendlyName;
		std::wstring Description;
		std::wstring DnsSuffix;
		std::wstring MacAddress;
		std::wstring OperStatus;
		std::wstring Type;
		std::wstring IpAddress;
		std::wstring Gateway;
	};

	void Refresh();
	void BuildToolBar();
	void BuildTable();

	static std::wstring FormatMacAddress(const BYTE* address, ULONG length);
	static PCWSTR IfTypeToString(ULONG type);

private:
	std::vector<AdapterInfo> _adapters;
};
