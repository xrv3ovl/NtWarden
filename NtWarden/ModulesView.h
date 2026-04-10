#pragma once
#include "DriverHelper.h"
#include "ViewBase.h"
#include <future>

struct ImGuiTableSortSpecsColumn;
class TabManager;

class ModulesView : public ViewBase {
public:
	ModulesView();
	void BuildWindow();
	void BuildToolBar();
	void RefreshNow();

	void BuildTable();

	std::wstring GetCompanyName(std::wstring path);

	void RefreshModules();

	// BYOVD enrichment
	void RunByovdScan();
	void PollByovdResult();

private:
	const ImGuiTableColumnSortSpecs* _specs = nullptr;
	bool _modalOpen : 1 = false, _killFailed : 1 = false;

	struct ModuleRow {
		std::string Name;
		std::string FullPath;
		unsigned long long ImageBase{ 0 };
		unsigned long ImageSize{ 0 };
		unsigned short LoadOrderIndex{ 0 };
		bool Filtered{ false };

		// BYOVD enrichment
		std::string Hash;
		bool IsKnownVulnerable{ false };
		bool HashMatch{ false };
		std::string CveId;
		std::string Description;
		std::string Category;
		std::string LolDriverId;
	};

	std::vector<std::shared_ptr<ModuleRow>> _modules;
	std::shared_ptr<ModuleRow> _selectedModule;

	// BYOVD scan state
	struct ByovdResult {
		std::string Name;
		std::string Hash;
		bool IsKnownVulnerable{ false };
		bool HashMatch{ false };
		std::string CveId;
		std::string Description;
		std::string Category;
		std::string LolDriverId;
	};
	std::future<std::vector<ByovdResult>> _byovdFuture;
	bool _byovdScanning{ false };
	bool _byovdScanned{ false };
	bool _showAllDrivers{ true };
};
