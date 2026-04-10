#pragma once
#include "imgui.h"
#include "implot.h"
#include <d3d11_1.h>
#include <chrono>
#include <iostream>
#include <iomanip>
#include <ctime>
class TabManager;

class PerformanceView {

public:

	static float CalculateCPULoad(ULONG64 idleTicks, ULONG64 totalTicks);
	static ULONG64 FileTimeToInt64(const FILETIME& ft) { return (((unsigned long long)(ft.dwHighDateTime)) << 32) | ((unsigned long long)ft.dwLowDateTime); }
	static float GetCPULoad();
	static void RenderPerfWindow(bool compact = false);

};


