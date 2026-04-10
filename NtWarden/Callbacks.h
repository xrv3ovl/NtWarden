#pragma once

#include <vector>
#include <string>

namespace Callbacks {

	static ImGuiTableFlags table_flags = ImGuiTableFlags_ScrollX |
		ImGuiTableFlags_ScrollY |
		ImGuiTableFlags_BordersV |
		ImGuiTableFlags_BordersOuterH |
		ImGuiTableFlags_RowBg |
		ImGuiTableFlags_Sortable |
		ImGuiTableFlags_ContextMenuInBody |
		ImGuiTableFlags_SortTristate |
		ImGuiTableFlags_Resizable;

	void RenderCallbackTables();
	void Refresh();

	// Callback integrity analysis
	struct IntegrityEntry {
		std::string DriverName;
		unsigned long long Address{ 0 };
		int CallbackType{ 0 };
		bool IsKnownEdr{ false };
		bool IsSuspicious{ false };
		std::string Details;
	};
	void ScanIntegrity();
	void RenderIntegrityTable();

	bool IsKnownEdrDriver(const std::string& name);
}
