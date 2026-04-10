#pragma once

#include <string>

namespace Utils {
	std::string WideToUtf8(const wchar_t* text);
	void ApplyClassicTheme();
	void ApplyLightTheme();
	void ApplyDarkTheme();
	void ApplyRedSamuraiTheme();
	void ApplyNeonBlueGreenTheme();
}
