#pragma once

#include "imgui.h"
#include <atlstr.h>

class ViewBase {
protected:
	explicit ViewBase(int defaultInterval = 1000) noexcept
		: _updateInterval(defaultInterval), _oldInterval(defaultInterval) {
	}

	void DrawFilterToolbar(float filterWidth = 100.0f) {
		ImGui::Separator();
		ImGui::SetNextItemWidth(filterWidth);
		if (ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_F))
			ImGui::SetKeyboardFocusHere();

		ImGui::InputText("Filter", _filterText, _countof(_filterText), ImGuiInputTextFlags_AutoSelectAll);

		ImGui::SameLine();
		if (ImGui::Button("Clear"))
			ClearFilter();
	}

	void DrawUpdateIntervalToolbar(const char* label = "##Update Interval", bool allowPause = true) {
		struct IntervalOption {
			const char* Text;
			int Interval;
		};
		static constexpr IntervalOption intervals[] = {
			{ "500 msec", 500 },
			{ "1 Second", 1000 },
			{ "2 Seconds", 2000 },
			{ "5 Seconds", 5000 },
			{ "Paused", 0 },
		};

		int current = 0;
		for (int i = 0; i < _countof(intervals); i++) {
			if (intervals[i].Interval == _updateInterval) {
				current = i;
				break;
			}
		}

		ImGui::Text("Update Interval");
		ImGui::SameLine(0, 6);
		ImGui::SetNextItemWidth(100);
		if (ImGui::BeginCombo(label, intervals[current].Text, ImGuiComboFlags_None)) {
			for (auto& item : intervals) {
				if (item.Interval == 0)
					break;
				if (ImGui::MenuItem(item.Text, nullptr, _updateInterval == item.Interval))
					_updateInterval = item.Interval;
			}
			if (allowPause) {
				ImGui::Separator();
				if (ImGui::MenuItem("Paused", "SPACE", _updateInterval == 0))
					TogglePause();
			}
			ImGui::EndCombo();
		}
	}

	bool IsUpdateDue() const {
		return _updateInterval > 0 && ::GetTickCount64() - _tick >= static_cast<DWORD64>(_updateInterval);
	}

	void MarkUpdated() noexcept {
		_tick = ::GetTickCount64();
	}

	void TogglePause() {
		if (_updateInterval == 0) {
			_updateInterval = _oldInterval > 0 ? _oldInterval : 1000;
		}
		else {
			_oldInterval = _updateInterval;
			_updateInterval = 0;
		}
	}

	CString GetFilterTextLower() const {
		CString filter;
		if (*_filterText) {
			filter = _filterText;
			filter.MakeLower();
		}
		return filter;
	}

	void ClearFilter() noexcept {
		*_filterText = 0;
	}

	char* FilterBuffer() noexcept {
		return _filterText;
	}

	int GetUpdateInterval() const noexcept {
		return _updateInterval;
	}

	void SetUpdateInterval(int interval) noexcept {
		_updateInterval = interval;
		if (interval > 0)
			_oldInterval = interval;
	}

private:
	DWORD64 _tick{ 0 };
	char _filterText[32]{};
	int _updateInterval{ 1000 };
	int _oldInterval{ 1000 };
};
