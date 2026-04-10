#pragma once

#include "ViewBase.h"

class KernelTimersView : public ViewBase {
public:
	KernelTimersView();
	void BuildWindow();
	void Refresh();

private:
	struct TimerCpuRow {
		ULONG Cpu;
		ULONG ContextSwitches;
		ULONG DpcCount;
		ULONG DpcRate;
		ULONG TimeIncrement;
		ULONG DpcBypassCount;
		ULONG ApcBypassCount;
	};

	void BuildToolBar();
	void BuildTable();

	std::vector<TimerCpuRow> _rows;
};
