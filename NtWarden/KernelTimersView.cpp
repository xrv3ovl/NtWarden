#include "pch.h"
#include "KernelTimersView.h"

#include "ImGuiExt.h"
#include "NativeSystem.h"
#include "RemoteClient.h"
#include "LoggerView.h"

KernelTimersView::KernelTimersView() : ViewBase(3000) {
}

void KernelTimersView::Refresh() {
	_rows.clear();

	if (RemoteClient::IsConnected()) {
		auto remote = RemoteClient::GetInterruptInfo();
		_rows.reserve(remote.size());
		for (ULONG i = 0; i < static_cast<ULONG>(remote.size()); i++) {
			TimerCpuRow row{};
			row.Cpu = i;
			row.ContextSwitches = remote[i].ContextSwitches;
			row.DpcCount = remote[i].DpcCount;
			row.DpcRate = remote[i].DpcRate;
			row.TimeIncrement = remote[i].TimeIncrement;
			row.DpcBypassCount = remote[i].DpcBypassCount;
			row.ApcBypassCount = remote[i].ApcBypassCount;
			_rows.push_back(std::move(row));
		}
		LoggerView::AddLog(LoggerView::UserModeLog, "Enumerated %zu DPC timer entries (remote)", _rows.size());
		return;
	}

	SYSTEM_INFO sysInfo{};
	::GetSystemInfo(&sysInfo);
	const auto cpuCount = sysInfo.dwNumberOfProcessors == 0 ? 1u : sysInfo.dwNumberOfProcessors;
	const auto bufferSize = sizeof(SYSTEM_INTERRUPT_INFORMATION_PRIVATE) * cpuCount;

	std::vector<BYTE> buffer(bufferSize);
	if (!NT_SUCCESS(::NtQuerySystemInformation(SystemInterruptInformationClass, buffer.data(), static_cast<ULONG>(buffer.size()), nullptr)))
		return;

	auto entries = reinterpret_cast<SYSTEM_INTERRUPT_INFORMATION_PRIVATE*>(buffer.data());
	_rows.reserve(cpuCount);
	for (ULONG i = 0; i < cpuCount; i++) {
		TimerCpuRow row{};
		row.Cpu = i;
		row.ContextSwitches = entries[i].ContextSwitches;
		row.DpcCount = entries[i].DpcCount;
		row.DpcRate = entries[i].DpcRate;
		row.TimeIncrement = entries[i].TimeIncrement;
		row.DpcBypassCount = entries[i].DpcBypassCount;
		row.ApcBypassCount = entries[i].ApcBypassCount;
		_rows.push_back(std::move(row));
	}

	LoggerView::AddLog(LoggerView::UserModeLog, "Enumerated %zu DPC timer entries across %lu CPUs", _rows.size(), cpuCount);
}

void KernelTimersView::BuildWindow() {
	BuildToolBar();
	if (IsUpdateDue()) {
		Refresh();
		MarkUpdated();
	}
	BuildTable();
}

void KernelTimersView::BuildToolBar() {
	ImGui::Separator();
	DrawUpdateIntervalToolbar("##KernelTimersInterval", false);
}

void KernelTimersView::BuildTable() {
	ImGui::TextUnformatted("This pass exposes per-CPU interrupt and DPC timing counters. Full DPC and IO timer enumeration still needs new KWinSys driver IOCTLs.");
	ImGui::Separator();

	if (ImGui::BeginTable("##KernelTimersTable", 7,
		ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
		ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable)) {
		ImGui::TableSetupScrollFreeze(0, 1);
		ImGui::TableSetupColumn("CPU");
		ImGui::TableSetupColumn("Context Switches");
		ImGui::TableSetupColumn("DPC Count");
		ImGui::TableSetupColumn("DPC Rate");
		ImGui::TableSetupColumn("Time Increment");
		ImGui::TableSetupColumn("DPC Bypass");
		ImGui::TableSetupColumn("APC Bypass");
		ImGui::TableHeadersRow();

		for (const auto& row : _rows) {
			ImGui::TableNextRow();
			ImGui::TableSetColumnIndex(0);
			ImGui::Text("%lu", row.Cpu);
			ImGui::TableSetColumnIndex(1);
			ImGui::Text("%lu", row.ContextSwitches);
			ImGui::TableSetColumnIndex(2);
			ImGui::Text("%lu", row.DpcCount);
			ImGui::TableSetColumnIndex(3);
			ImGui::Text("%lu", row.DpcRate);
			ImGui::TableSetColumnIndex(4);
			ImGui::Text("%lu", row.TimeIncrement);
			ImGui::TableSetColumnIndex(5);
			ImGui::Text("%lu", row.DpcBypassCount);
			ImGui::TableSetColumnIndex(6);
			ImGui::Text("%lu", row.ApcBypassCount);
		}
		ImGui::EndTable();
	}
}
