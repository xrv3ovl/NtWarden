#include "pch.h"
#include "imgui.h"
#include "HypervisorHookView.h"
#include "RemoteClient.h"
#include "LoggerView.h"
#include <intrin.h>

using namespace ImGui;

HypervisorHookView::HypervisorHookView() : ViewBase(0) {}

void HypervisorHookView::RefreshNow() { ScanHypervisorHooks(); MarkUpdated(); }

void HypervisorHookView::BuildWindow() { BuildHypervisorHookTable(); }

void HypervisorHookView::ScanHypervisorHooks() {
	_hypervisorHooks.clear();

	if (RemoteClient::IsConnected()) {
		auto remoteEntries = RemoteClient::GetHypervisorHooks();
		for (auto& re : remoteEntries) {
			HypervisorHookEntry entry;
			entry.FunctionName = re.FunctionName;
			entry.AvgCycles = re.AvgCycles;
			entry.BaselineCycles = re.BaselineCycles;
			entry.TimingAnomaly = re.TimingAnomaly != 0;
			_hypervisorHooks.push_back(std::move(entry));
		}
		return;
	}

	int cpuInfo[4]{};

	unsigned long long baselineTotal = 0;
	for (int i = 0; i < 1000; i++) {
		unsigned long long s = __rdtsc();
		unsigned long long e = __rdtsc();
		baselineTotal += (e - s);
	}
	unsigned long long baselineCycles = baselineTotal / 1000;

	// CPUID leaf 0
	{
		unsigned long long total = 0;
		for (int i = 0; i < 1000; i++) {
			unsigned long long s = __rdtsc();
			__cpuid(cpuInfo, 0);
			unsigned long long e = __rdtsc();
			total += (e - s);
		}
		HypervisorHookEntry entry;
		entry.FunctionName = "CPUID (leaf 0)";
		entry.AvgCycles = total / 1000;
		entry.BaselineCycles = baselineCycles;
		entry.TimingAnomaly = (entry.AvgCycles > 1000);
		_hypervisorHooks.push_back(std::move(entry));
	}

	// CPUID leaf 1
	{
		unsigned long long total = 0;
		for (int i = 0; i < 1000; i++) {
			unsigned long long s = __rdtsc();
			__cpuid(cpuInfo, 1);
			unsigned long long e = __rdtsc();
			total += (e - s);
		}
		HypervisorHookEntry entry;
		entry.FunctionName = "CPUID (leaf 1)";
		entry.AvgCycles = total / 1000;
		entry.BaselineCycles = baselineCycles;
		entry.TimingAnomaly = (entry.AvgCycles > 1000);
		_hypervisorHooks.push_back(std::move(entry));
	}

	// CPUID hypervisor leaf
	{
		unsigned long long total = 0;
		for (int i = 0; i < 1000; i++) {
			unsigned long long s = __rdtsc();
			__cpuid(cpuInfo, 0x40000000);
			unsigned long long e = __rdtsc();
			total += (e - s);
		}
		HypervisorHookEntry entry;
		entry.FunctionName = "CPUID (leaf 0x40000000)";
		entry.AvgCycles = total / 1000;
		entry.BaselineCycles = baselineCycles;
		entry.TimingAnomaly = (entry.AvgCycles > 1500);
		_hypervisorHooks.push_back(std::move(entry));
	}

	// CPUID leaf 0x80000001
	{
		unsigned long long total = 0;
		for (int i = 0; i < 1000; i++) {
			unsigned long long s = __rdtsc();
			__cpuid(cpuInfo, 0x80000001);
			unsigned long long e = __rdtsc();
			total += (e - s);
		}
		HypervisorHookEntry entry;
		entry.FunctionName = "CPUID (leaf 0x80000001)";
		entry.AvgCycles = total / 1000;
		entry.BaselineCycles = baselineCycles;
		entry.TimingAnomaly = (entry.AvgCycles > 1000);
		_hypervisorHooks.push_back(std::move(entry));
	}
}

void HypervisorHookView::BuildHypervisorHookTable() {
	if (_hypervisorHooks.empty()) ScanHypervisorHooks();
	if (_hypervisorHooks.empty()) return;

	int anomalyCount = 0;
	for (auto& e : _hypervisorHooks) if (e.TimingAnomaly) anomalyCount++;

	if (anomalyCount > 0)
		TextColored(ImVec4(1.0f, 0.6f, 0.0f, 1.0f), "%d timing anomaly(ies) - possible EPT/VTx hooks", anomalyCount);
	else
		TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), "No significant timing anomalies detected.");

	TextDisabled("Threshold: >1000 cycles for CPUID indicates potential hypervisor interception.");
	Separator();

	if (BeginTable("hvHookTable", 4, ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg)) {
		TableSetupScrollFreeze(1, 1);
		TableSetupColumn("Operation");
		TableSetupColumn("Avg Cycles", ImGuiTableColumnFlags_WidthFixed, 100.0f);
		TableSetupColumn("Baseline", ImGuiTableColumnFlags_WidthFixed, 80.0f);
		TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed, 120.0f);
		TableHeadersRow();

		for (const auto& entry : _hypervisorHooks) {
			TableNextRow();
			if (entry.TimingAnomaly) TableSetBgColor(ImGuiTableBgTarget_RowBg0, IM_COL32(180, 100, 0, 60));
			TableSetColumnIndex(0); Text("%s", entry.FunctionName.c_str());
			TableSetColumnIndex(1); Text("%llu", entry.AvgCycles);
			TableSetColumnIndex(2); Text("%llu", entry.BaselineCycles);
			TableSetColumnIndex(3);
			if (entry.TimingAnomaly)
				TextColored(ImVec4(1.0f, 0.6f, 0.0f, 1.0f), "ANOMALY");
			else
				TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), "Normal");
		}
		EndTable();
	}
}
