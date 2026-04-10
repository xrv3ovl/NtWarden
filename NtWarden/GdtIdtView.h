#pragma once

#include "ViewBase.h"
#include "../KWinSys/KWinSysPublic.h"
#include <future>

class GdtIdtView {
public:
	void BuildWindow();
	void RefreshNow();

private:
	void RefreshGdt();
	void RefreshIdt();
	void BuildGdtTab();
	void BuildIdtTab();

	GDT_INFO _gdtInfo{};
	IDT_INFO _idtInfo{};
	bool _gdtLoaded{ false };
	bool _idtLoaded{ false };
	bool _gdtLoading{ false };
	bool _idtLoading{ false };
	std::future<GDT_INFO> _gdtFuture;
	std::future<IDT_INFO> _idtFuture;
};
