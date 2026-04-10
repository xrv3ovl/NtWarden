#include "pch.h"
#include "Utils.h"
#include "imgui.h"
#include "implot.h"

namespace Utils {
	namespace {
		void ApplySharedStyleTuning() {
			auto& style = ImGui::GetStyle();
			style.WindowRounding = 2.0f;
			style.ChildRounding = 2.0f;
			style.FrameRounding = 2.0f;
			style.PopupRounding = 2.0f;
			style.ScrollbarRounding = 3.0f;
			style.GrabRounding = 2.0f;
			style.TabRounding = 2.0f;
			style.FrameBorderSize = 1.0f;
			style.WindowBorderSize = 1.0f;
		}

		void ApplyRedSamuraiPlotTheme() {
			ImPlot::StyleColorsDark();
			auto& plotStyle = ImPlot::GetStyle();
			auto* colors = plotStyle.Colors;
			plotStyle.MinorAlpha = 0.25f;
			colors[ImPlotCol_FrameBg] = ImVec4(0.22f, 0.08f, 0.02f, 0.55f);
			colors[ImPlotCol_PlotBg] = ImVec4(0.05f, 0.01f, 0.01f, 0.75f);
			colors[ImPlotCol_PlotBorder] = ImVec4(0.82f, 0.40f, 0.08f, 0.65f);
			colors[ImPlotCol_LegendBg] = ImVec4(0.07f, 0.02f, 0.02f, 0.88f);
			colors[ImPlotCol_LegendBorder] = ImVec4(0.82f, 0.40f, 0.08f, 0.55f);
			colors[ImPlotCol_LegendText] = ImVec4(0.98f, 0.88f, 0.72f, 1.00f);
			colors[ImPlotCol_TitleText] = ImVec4(1.00f, 0.82f, 0.38f, 1.00f);
			colors[ImPlotCol_InlayText] = ImVec4(0.98f, 0.88f, 0.72f, 1.00f);
			colors[ImPlotCol_AxisText] = ImVec4(0.98f, 0.88f, 0.72f, 1.00f);
			colors[ImPlotCol_AxisGrid] = ImVec4(0.85f, 0.40f, 0.10f, 0.18f);
			colors[ImPlotCol_Selection] = ImVec4(1.00f, 0.72f, 0.14f, 1.00f);
			colors[ImPlotCol_Crosshairs] = ImVec4(1.00f, 0.82f, 0.38f, 0.45f);
		}

		void ApplyNeonBlueGreenPlotTheme() {
			ImPlot::StyleColorsDark();
			auto& plotStyle = ImPlot::GetStyle();
			auto* colors = plotStyle.Colors;
			plotStyle.MinorAlpha = 0.22f;
			colors[ImPlotCol_FrameBg] = ImVec4(0.02f, 0.09f, 0.11f, 0.58f);
			colors[ImPlotCol_PlotBg] = ImVec4(0.01f, 0.03f, 0.05f, 0.82f);
			colors[ImPlotCol_PlotBorder] = ImVec4(0.12f, 0.92f, 0.84f, 0.55f);
			colors[ImPlotCol_LegendBg] = ImVec4(0.01f, 0.05f, 0.08f, 0.90f);
			colors[ImPlotCol_LegendBorder] = ImVec4(0.20f, 0.72f, 1.00f, 0.55f);
			colors[ImPlotCol_LegendText] = ImVec4(0.86f, 1.00f, 0.98f, 1.00f);
			colors[ImPlotCol_TitleText] = ImVec4(0.44f, 0.94f, 1.00f, 1.00f);
			colors[ImPlotCol_InlayText] = ImVec4(0.86f, 1.00f, 0.98f, 1.00f);
			colors[ImPlotCol_AxisText] = ImVec4(0.70f, 0.97f, 0.93f, 1.00f);
			colors[ImPlotCol_AxisGrid] = ImVec4(0.12f, 0.82f, 0.82f, 0.16f);
			colors[ImPlotCol_Selection] = ImVec4(0.17f, 0.94f, 0.56f, 1.00f);
			colors[ImPlotCol_Crosshairs] = ImVec4(0.30f, 0.86f, 1.00f, 0.45f);
		}
	}

	std::string WideToUtf8(const wchar_t* text) {
		if (!text || !*text)
			return {};

		auto length = ::WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
		if (length <= 1)
			return {};

		std::string utf8(length - 1, '\0');
		::WideCharToMultiByte(CP_UTF8, 0, text, -1, utf8.data(), length, nullptr, nullptr);
		return utf8;
	}

	void ApplyClassicTheme() {
		ImGui::StyleColorsClassic();
		ImPlot::StyleColorsClassic();
		ApplySharedStyleTuning();
	}

	void ApplyLightTheme() {
		ImGui::StyleColorsLight();
		ImPlot::StyleColorsLight();
		ApplySharedStyleTuning();
	}

	void ApplyDarkTheme() {
		ImGui::StyleColorsDark();
		ImPlot::StyleColorsDark();
		ApplySharedStyleTuning();
	}

	void ApplyRedSamuraiTheme() {
		ImGui::StyleColorsRedSamurai();
		ApplyRedSamuraiPlotTheme();
		ApplySharedStyleTuning();
	}

	void ApplyNeonBlueGreenTheme() {
		ImGui::StyleColorsDark();
		auto& style = ImGui::GetStyle();
		auto* colors = style.Colors;

		colors[ImGuiCol_Text] = ImVec4(0.82f, 1.00f, 0.96f, 1.00f);
		colors[ImGuiCol_TextDisabled] = ImVec4(0.36f, 0.72f, 0.70f, 1.00f);
		colors[ImGuiCol_WindowBg] = ImVec4(0.01f, 0.03f, 0.05f, 0.96f);
		colors[ImGuiCol_ChildBg] = ImVec4(0.01f, 0.06f, 0.09f, 0.40f);
		colors[ImGuiCol_PopupBg] = ImVec4(0.02f, 0.05f, 0.08f, 0.96f);
		colors[ImGuiCol_Border] = ImVec4(0.10f, 0.88f, 0.82f, 0.42f);
		colors[ImGuiCol_BorderShadow] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
		colors[ImGuiCol_FrameBg] = ImVec4(0.03f, 0.16f, 0.18f, 0.74f);
		colors[ImGuiCol_FrameBgHovered] = ImVec4(0.10f, 0.34f, 0.38f, 0.80f);
		colors[ImGuiCol_FrameBgActive] = ImVec4(0.12f, 0.52f, 0.50f, 0.92f);
		colors[ImGuiCol_TitleBg] = ImVec4(0.01f, 0.07f, 0.10f, 1.00f);
		colors[ImGuiCol_TitleBgActive] = ImVec4(0.03f, 0.24f, 0.30f, 1.00f);
		colors[ImGuiCol_TitleBgCollapsed] = ImVec4(0.01f, 0.04f, 0.06f, 0.90f);
		colors[ImGuiCol_MenuBarBg] = ImVec4(0.01f, 0.06f, 0.09f, 1.00f);
		colors[ImGuiCol_ScrollbarBg] = ImVec4(0.01f, 0.03f, 0.05f, 0.70f);
		colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.10f, 0.34f, 0.38f, 0.95f);
		colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.17f, 0.70f, 0.80f, 0.95f);
		colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.18f, 0.86f, 0.98f, 1.00f);
		colors[ImGuiCol_CheckMark] = ImVec4(0.18f, 0.96f, 0.58f, 1.00f);
		colors[ImGuiCol_SliderGrab] = ImVec4(0.20f, 0.74f, 1.00f, 0.88f);
		colors[ImGuiCol_SliderGrabActive] = ImVec4(0.19f, 0.97f, 0.60f, 1.00f);
		colors[ImGuiCol_Button] = ImVec4(0.08f, 0.42f, 0.50f, 0.58f);
		colors[ImGuiCol_ButtonHovered] = ImVec4(0.14f, 0.70f, 0.84f, 0.86f);
		colors[ImGuiCol_ButtonActive] = ImVec4(0.16f, 0.92f, 0.76f, 0.92f);
		colors[ImGuiCol_Header] = ImVec4(0.06f, 0.34f, 0.36f, 0.76f);
		colors[ImGuiCol_HeaderHovered] = ImVec4(0.14f, 0.68f, 0.82f, 0.84f);
		colors[ImGuiCol_HeaderActive] = ImVec4(0.17f, 0.96f, 0.58f, 0.86f);
		colors[ImGuiCol_Separator] = ImVec4(0.10f, 0.88f, 0.82f, 0.34f);
		colors[ImGuiCol_SeparatorHovered] = ImVec4(0.24f, 0.84f, 1.00f, 0.78f);
		colors[ImGuiCol_SeparatorActive] = ImVec4(0.19f, 0.97f, 0.60f, 0.90f);
		colors[ImGuiCol_ResizeGrip] = ImVec4(0.18f, 0.86f, 0.98f, 0.28f);
		colors[ImGuiCol_ResizeGripHovered] = ImVec4(0.20f, 0.92f, 1.00f, 0.66f);
		colors[ImGuiCol_ResizeGripActive] = ImVec4(0.19f, 0.97f, 0.60f, 0.90f);
		colors[ImGuiCol_Tab] = ImVec4(0.03f, 0.16f, 0.20f, 0.92f);
		colors[ImGuiCol_TabHovered] = ImVec4(0.12f, 0.54f, 0.70f, 0.90f);
		colors[ImGuiCol_TabActive] = ImVec4(0.10f, 0.38f, 0.52f, 1.00f);
		colors[ImGuiCol_TabUnfocused] = ImVec4(0.01f, 0.07f, 0.10f, 0.96f);
		colors[ImGuiCol_TabUnfocusedActive] = ImVec4(0.03f, 0.20f, 0.28f, 1.00f);
		colors[ImGuiCol_DockingPreview] = ImVec4(0.16f, 0.88f, 0.94f, 0.36f);
		colors[ImGuiCol_DockingEmptyBg] = ImVec4(0.01f, 0.02f, 0.03f, 1.00f);
		colors[ImGuiCol_PlotLines] = ImVec4(0.22f, 0.92f, 0.78f, 1.00f);
		colors[ImGuiCol_PlotLinesHovered] = ImVec4(0.26f, 0.84f, 1.00f, 1.00f);
		colors[ImGuiCol_PlotHistogram] = ImVec4(0.15f, 0.94f, 0.58f, 1.00f);
		colors[ImGuiCol_PlotHistogramHovered] = ImVec4(0.20f, 1.00f, 0.76f, 1.00f);
		colors[ImGuiCol_TableHeaderBg] = ImVec4(0.02f, 0.13f, 0.16f, 1.00f);
		colors[ImGuiCol_TableBorderStrong] = ImVec4(0.10f, 0.58f, 0.64f, 0.85f);
		colors[ImGuiCol_TableBorderLight] = ImVec4(0.06f, 0.26f, 0.30f, 0.90f);
		colors[ImGuiCol_TableRowBg] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
		colors[ImGuiCol_TableRowBgAlt] = ImVec4(0.10f, 0.40f, 0.42f, 0.12f);
		colors[ImGuiCol_TextSelectedBg] = ImVec4(0.18f, 0.86f, 0.98f, 0.24f);
		colors[ImGuiCol_DragDropTarget] = ImVec4(0.18f, 0.96f, 0.58f, 0.90f);
		colors[ImGuiCol_NavHighlight] = ImVec4(0.18f, 0.86f, 0.98f, 0.85f);
		colors[ImGuiCol_NavWindowingHighlight] = ImVec4(0.86f, 0.98f, 1.00f, 0.70f);
		colors[ImGuiCol_NavWindowingDimBg] = ImVec4(0.00f, 0.12f, 0.16f, 0.28f);
		colors[ImGuiCol_ModalWindowDimBg] = ImVec4(0.00f, 0.08f, 0.10f, 0.42f);

		ApplyNeonBlueGreenPlotTheme();
		ApplySharedStyleTuning();
	}
}
