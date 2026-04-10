#pragma once

#include "imgui.h"
#include <vector>
#include <string>

struct MiniFilterEntry {
	std::wstring FilterName;
	std::wstring Altitude;
	ULONG FrameID;
	ULONG NumberOfInstances;
};

struct MiniFilterInstanceEntry {
	std::wstring InstanceName;
	std::wstring VolumeName;
	std::wstring Altitude;
};

class MiniFilterView {
public:
	void BuildWindow();
	void Refresh();

private:
	std::vector<MiniFilterEntry> _filters;
	std::vector<MiniFilterInstanceEntry> _instances;
	bool _needsRefresh = true;
	bool _loadFailed = false;
	int _selectedFilter = -1;
	std::wstring _selectedFilterName;

	static ImGuiTableFlags table_flags;
};
