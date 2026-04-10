#include "LoggerView.h"

#include <fstream>
#include <shellapi.h>

namespace {
	ImVector<char*> UserItems;
	ImVector<char*> KernelItems;
	ImVector<char*> AllItems;
	ImGuiTextFilter Filter;
	bool AutoScroll = true;
	bool ScrollToBottom = false;

	struct SelectionState {
		int Anchor = -1;
		int Start = -1;
		int End = -1;
	};

	SelectionState UserSelection;
	SelectionState KernelSelection;
	SelectionState AllSelection;

	const char* GetLogTypeName(int logtype_code) {
		return logtype_code == LoggerView::KernelDriverLog ? "kernel-driver" : "user";
	}

	std::string GetExeDirectory() {
		char path[MAX_PATH]{};
		::GetModuleFileNameA(nullptr, path, _countof(path));
		char* slash = strrchr(path, '\\');
		if (slash)
			*slash = 0;
		return path;
	}

	std::string GetCombinedLogFilePath() {
		return GetExeDirectory() + "\\NtWarden.log";
	}

	std::string GetTypedLogFilePath(int logtype_code) {
		return GetExeDirectory() + (logtype_code == LoggerView::KernelDriverLog ? "\\NtWarden.kernel-driver.log" : "\\NtWarden.user.log");
	}

	void AppendLineToFile(const std::string& path, const char* text) {
		std::ofstream stream(path, std::ios::out | std::ios::app | std::ios::binary);
		if (stream)
			stream << text << "\r\n";
	}

	void RewriteLogFile(const std::string& path, const ImVector<char*>& items) {
		std::ofstream stream(path, std::ios::out | std::ios::trunc | std::ios::binary);
		if (!stream)
			return;
		for (int i = 0; i < items.Size; i++)
			stream << items[i] << "\r\n";
	}

	void RewriteAllLogFiles() {
		RewriteLogFile(GetCombinedLogFilePath(), AllItems);
		RewriteLogFile(GetTypedLogFilePath(LoggerView::UserModeLog), UserItems);
		RewriteLogFile(GetTypedLogFilePath(LoggerView::KernelDriverLog), KernelItems);
	}

	void ClearItems(ImVector<char*>& items, SelectionState& selection) {
		for (int i = 0; i < items.Size; i++)
			free(items[i]);
		items.clear();
		selection = {};
	}

	void RebuildAllItems() {
		ClearItems(AllItems, AllSelection);
		for (int i = 0; i < UserItems.Size; i++)
			AllItems.push_back(LoggerView::Strdup(UserItems[i]));
		for (int i = 0; i < KernelItems.Size; i++)
			AllItems.push_back(LoggerView::Strdup(KernelItems[i]));
	}

	std::string BuildVisibleLogText(const ImVector<char*>& items) {
		std::string text;
		for (int i = 0; i < items.Size; i++) {
			const char* item = items[i];
			if (!Filter.PassFilter(item))
				continue;
			text += item;
			text += "\r\n";
		}
		return text;
	}

	void CopyTextToClipboard(const std::string& text) {
		if (!text.empty())
			ImGui::SetClipboardText(text.c_str());
	}

	void OpenPath(const std::string& path) {
		::ShellExecuteA(nullptr, "open", path.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
	}

	bool HasSelection(const SelectionState& selection) {
		return selection.Start >= 0 && selection.End >= selection.Start;
	}

	void SetSelection(SelectionState& selection, int index) {
		selection.Anchor = index;
		selection.Start = index;
		selection.End = index;
	}

	void ExtendSelection(SelectionState& selection, int index) {
		if (selection.Anchor < 0) {
			SetSelection(selection, index);
			return;
		}
		selection.Start = selection.Anchor < index ? selection.Anchor : index;
		selection.End = selection.Anchor > index ? selection.Anchor : index;
	}

	bool IsSelected(const SelectionState& selection, int index) {
		return HasSelection(selection) && index >= selection.Start && index <= selection.End;
	}

	std::string BuildSelectedLogText(const ImVector<char*>& items, const SelectionState& selection) {
		if (!HasSelection(selection))
			return {};
		std::string text;
		for (int i = selection.Start; i <= selection.End && i < items.Size; i++) {
			if (!Filter.PassFilter(items[i]))
				continue;
			text += items[i];
			text += "\r\n";
		}
		return text;
	}

	float GetWrappedLogRowHeight(const char* text, float wrapWidth) {
		if (wrapWidth <= 0.0f)
			return ImGui::GetTextLineHeightWithSpacing();

		const auto textSize = ImGui::CalcTextSize(text, nullptr, false, wrapWidth);
		const auto verticalPadding = ImGui::GetStyle().FramePadding.y * 2.0f;
		return (textSize.y > 0.0f ? textSize.y : ImGui::GetTextLineHeight()) + verticalPadding;
	}

	// Returns true when the UI background is light (luminance > 0.5)
	bool IsLightTheme() {
		const ImVec4& bg = ImGui::GetStyle().Colors[ImGuiCol_WindowBg];
		// Perceived luminance: 0.299R + 0.587G + 0.114B
		const float lum = bg.x * 0.299f + bg.y * 0.587f + bg.z * 0.114f;
		return lum > 0.5f;
	}

	ImVec4 GetLineColor(const char* text) {
		const bool light = IsLightTheme();
		if (strstr(text, "[kernel-driver]"))
			return light
				? ImVec4(0.65f, 0.42f, 0.00f, 1.0f)  // dark amber
				: ImVec4(1.00f, 0.78f, 0.28f, 1.0f); // bright amber
		if (strstr(text, "[user]"))
			return light
				? ImVec4(0.08f, 0.38f, 0.72f, 1.0f)  // deep blue
				: ImVec4(0.50f, 0.82f, 1.00f, 1.0f); // sky blue
		if (strstr(text, "[error]") || strstr(text, "failed") || strstr(text, "Failed"))
			return light
				? ImVec4(0.82f, 0.10f, 0.10f, 1.0f)  // deep red
				: ImVec4(1.00f, 0.42f, 0.42f, 1.0f); // light red
		if (strstr(text, "success") || strstr(text, "successfully") || strstr(text, "succ"))
			return light
				? ImVec4(0.08f, 0.52f, 0.18f, 1.0f)  // forest green
				: ImVec4(0.45f, 1.00f, 0.55f, 1.0f); // lime green
		return ImGui::GetStyleColorVec4(ImGuiCol_Text);
	}
}

void LoggerView::AddLog(int logtype_code, const char* fmt, ...) {
	time_t rawtime;
	struct tm* timeinfo;
	char timestamp[80];

	time(&rawtime);
	timeinfo = localtime(&rawtime);
	strftime(timestamp, sizeof(timestamp), "[%H:%M:%S]", timeinfo);

	char buf[1024];
	va_list args;
	va_start(args, fmt);
	vsnprintf(buf, IM_ARRAYSIZE(buf), fmt, args);
	buf[IM_ARRAYSIZE(buf) - 1] = 0;
	va_end(args);

	char line[1200];
	sprintf_s(line, "%s [%s] %s", timestamp, GetLogTypeName(logtype_code), buf);

	AllItems.push_back(Strdup(line));
	if (logtype_code == UserModeLog)
		UserItems.push_back(Strdup(line));
	else if (logtype_code == KernelDriverLog)
		KernelItems.push_back(Strdup(line));

	AppendLineToFile(GetCombinedLogFilePath(), line);
	AppendLineToFile(GetTypedLogFilePath(logtype_code), line);
	ScrollToBottom = true;
}

void LoggerView::ClearLog(int logtype_code) {
	if (logtype_code == LoggerView::UserModeLog)
		ClearItems(UserItems, UserSelection);
	else if (logtype_code == LoggerView::KernelDriverLog)
		ClearItems(KernelItems, KernelSelection);

	RebuildAllItems();
	RewriteAllLogFiles();
}

void LoggerView::RenderLogWindow() {
	const char* items[] = { "All Logs", "User Mode Logs", "Kernel Driver Logs" };
	static int item_current_idx = 0;
	const char* combo_preview_value = items[item_current_idx];
	ImGui::SetNextItemWidth(160.f);
	if (ImGui::BeginCombo("##LogTypeCombo", combo_preview_value, 0)) {
		for (int n = 0; n < IM_ARRAYSIZE(items); n++) {
			const bool is_selected = (item_current_idx == n);
			if (ImGui::Selectable(items[n], is_selected))
				item_current_idx = n;
			if (is_selected)
				ImGui::SetItemDefaultFocus();
		}
		ImGui::EndCombo();
	}
	ImGui::SameLine();
	if (ImGui::Button("Open Log"))
		OpenPath(GetCombinedLogFilePath());
	ImGui::SameLine();
	if (ImGui::Button("Folder"))
		OpenPath(GetExeDirectory());
	ImGui::SameLine();
	if (ImGui::Button("Clear UI")) {
		if (item_current_idx == 0) {
			ClearItems(UserItems, UserSelection);
			ClearItems(KernelItems, KernelSelection);
			ClearItems(AllItems, AllSelection);
			RewriteAllLogFiles();
		}
		else if (item_current_idx == 1) {
			LoggerView::ClearLog(UserModeLog);
		}
		else {
			LoggerView::ClearLog(KernelDriverLog);
		}
	}
	ImGui::SameLine();
	ImGui::Checkbox("AutoScroll", &AutoScroll);
	ImGui::SameLine();
	Filter.Draw("Filter", 180);
	ImGui::TextDisabled("%s", GetCombinedLogFilePath().c_str());

	const float footer_height_to_reserve = ImGui::GetStyle().ItemSpacing.y + ImGui::GetFrameHeightWithSpacing();
	if (ImGui::BeginChild("##ScrollingRegion", ImVec2(0, -footer_height_to_reserve), false)) {
		ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(4, 1));

		const ImVector<char*>* source = &AllItems;
		SelectionState* selection = &AllSelection;
		if (item_current_idx == 1) {
			source = &UserItems;
			selection = &UserSelection;
		}
		else if (item_current_idx == 2) {
			source = &KernelItems;
			selection = &KernelSelection;
		}

		for (int i = 0; i < source->Size; i++) {
			const char* item = (*source)[i];
			if (!Filter.PassFilter(item))
				continue;

			const float rowWidth = ImGui::GetContentRegionAvail().x;
			const float wrapWidth = (rowWidth > 0.0f) ? (rowWidth - ImGui::GetStyle().FramePadding.x * 2.0f) : 0.0f;
			const float rowHeight = GetWrappedLogRowHeight(item, wrapWidth);

			ImGui::PushID(i);
			const ImVec2 rowStart = ImGui::GetCursorScreenPos();
			const bool selected = IsSelected(*selection, i);
			if (ImGui::InvisibleButton("##LogLine", ImVec2(-FLT_MIN, rowHeight))) {
				if (ImGui::GetIO().KeyShift)
					ExtendSelection(*selection, i);
				else
					SetSelection(*selection, i);
			}
			if (ImGui::IsItemClicked(ImGuiMouseButton_Right) && !selected)
				SetSelection(*selection, i);

			const ImVec2 rectMin = ImGui::GetItemRectMin();
			const ImVec2 rectMax = ImGui::GetItemRectMax();
			ImU32 bg = 0;
			if (selected) {
				bg = IsLightTheme()
					? ImGui::GetColorU32(ImVec4(0.18f, 0.40f, 0.80f, 0.30f))  // light: blue tint
					: ImGui::GetColorU32(ImVec4(0.20f, 0.32f, 0.52f, 0.65f)); // dark: dark blue
			} else if (ImGui::IsItemHovered()) {
				bg = IsLightTheme()
					? ImGui::GetColorU32(ImVec4(0.18f, 0.40f, 0.80f, 0.10f))  // light: subtle blue
					: ImGui::GetColorU32(ImVec4(0.24f, 0.38f, 0.60f, 0.22f)); // dark: subtle blue
			}
			if (bg != 0)
				ImGui::GetWindowDrawList()->AddRectFilled(rectMin, rectMax, bg);

			ImGui::SetCursorScreenPos(ImVec2(rowStart.x + ImGui::GetStyle().FramePadding.x, rowStart.y + ImGui::GetStyle().FramePadding.y));
			ImGui::PushTextWrapPos(rowStart.x + rowWidth);
			ImGui::PushStyleColor(ImGuiCol_Text, GetLineColor(item));
			ImGui::TextUnformatted(item);
			ImGui::PopStyleColor();
			ImGui::PopTextWrapPos();
			ImGui::SetCursorScreenPos(ImVec2(rowStart.x, rowStart.y + rowHeight));
			if (ImGui::BeginPopupContextItem("##LogLineContext")) {
				if (ImGui::MenuItem("Copy Selected"))
					CopyTextToClipboard(BuildSelectedLogText(*source, *selection));
				if (ImGui::MenuItem("Copy Visible"))
					CopyTextToClipboard(BuildVisibleLogText(*source));
				ImGui::EndPopup();
			}
			ImGui::PopID();
		}

		if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) && ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_C)) {
			auto selectedText = BuildSelectedLogText(*source, *selection);
			if (!selectedText.empty())
				CopyTextToClipboard(selectedText);
			else
				CopyTextToClipboard(BuildVisibleLogText(*source));
		}

		if (ScrollToBottom || (AutoScroll && ImGui::GetScrollY() >= ImGui::GetScrollMaxY()))
			ImGui::SetScrollHereY(1.0f);
		ScrollToBottom = false;

		ImGui::PopStyleVar();
		ImGui::EndChild();
	}
}

