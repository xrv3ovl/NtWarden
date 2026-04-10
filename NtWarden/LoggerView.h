#pragma once
#include "imgui.h"
#include <d3d11_1.h>
#include <chrono>
#include <iostream>
#include <iomanip>
#include <ctime>

class TabManager;

class LoggerView {

public:
	enum LogType { UserModeLog, KernelDriverLog, KernelModeLog = KernelDriverLog };
	static void AddLog(int logtype_code, const char* fmt, ...);
	static void ClearLog(int logtype_code);
	static char* Strdup(const char* s) { IM_ASSERT(s); size_t len = strlen(s) + 1; void* buf = malloc(len); IM_ASSERT(buf); return (char*)memcpy(buf, (const void*)s, len); }
	static void RenderLogWindow();

};

