#pragma once
#include "ViewBase.h"

struct ImGuiTableSortSpecsColumn;
class TabManager;

class ETWView : public ViewBase {
public:
	ETWView();
	void BuildWindow();
	void BuildToolBar();
	void RefreshNow();

private:
	struct SessionInfo {
		std::wstring Name;
		ULONG BufferSizeMb{ 0 };
		ULONG BuffersWritten{ 0 };
		ULONG EventsLost{ 0 };
		ULONG LogFileMode{ 0 };
	};

	struct ProviderInfo {
		std::wstring Name;
		std::wstring Guid;
	};

	void Refresh();
	void BuildSessionsTable();
	void BuildProvidersTable();

	const ImGuiTableColumnSortSpecs* _specs = nullptr;
	bool _modalOpen : 1 = false, _killFailed : 1 = false;
	std::vector<SessionInfo> _sessions;
	std::vector<ProviderInfo> _providers;

};
