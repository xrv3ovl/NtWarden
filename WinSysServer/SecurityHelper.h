#pragma once
#include <Windows.h>

struct SecurityHelper abstract final {
	static bool IsRunningElevated();
};
