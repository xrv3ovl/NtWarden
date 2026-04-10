#include "pch.h"
#include "Settings.h"
#include "colors.h"
#include "FormatHelper.h"

using namespace ImGui;

Settings::Settings() {
	auto& black = StandardColors::Black;
	auto& white = StandardColors::White;

	ProcessColors = {
		ProcessColor("New Objects", FormatHelper::ColorWithAlpha(StandardColors::DarkGreen, .7f), white),
		ProcessColor("Deleted Objects", FormatHelper::ColorWithAlpha(StandardColors::DarkRed, .7f), white),
		ProcessColor("Managed (.NET)", FormatHelper::ColorWithAlpha(ImVec4(.113f, .701f, .034f, .700f), .7f), black),
		ProcessColor("Immersive", FormatHelper::ColorWithAlpha(ImVec4(.140f, .681f, .681f, .700f), .7f), black),
		ProcessColor("Services", FormatHelper::ColorWithAlpha(ImVec4(.809f, .440f, .504f, .700f), .7f), black),
		ProcessColor("Protected", FormatHelper::ColorWithAlpha(ImVec4(.520f, .092f, .520f, .700f), .7f), white),
		ProcessColor("Secure", FormatHelper::ColorWithAlpha(StandardColors::Purple, .7f), white),
		ProcessColor("In Job", FormatHelper::ColorWithAlpha(StandardColors::Brown, .7f), white, false),
	};
}
