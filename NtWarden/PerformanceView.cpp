#include "PerformanceView.h"
#include "Globals.h"
#include "RemoteClient.h"
#include <iphlpapi.h>
#include <pdh.h>
#include <pdhmsg.h>
#include <algorithm>
#include <vector>

#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Pdh.lib")
#pragma comment(lib, "dxgi.lib")

#include <dxgi.h>

namespace {
	std::string FormatRemoteWindowsVersion(const SysInfoNet& sysInfo) {
		char build[64]{};
		sprintf_s(build, "%u.%u.%u.%u",
			sysInfo.MajorVersion,
			sysInfo.MinorVersion,
			sysInfo.BuildNumber,
			sysInfo.Revision);

		if (sysInfo.ProductName[0] != '\0' && sysInfo.DisplayVersion[0] != '\0') {
			char buffer[256]{};
			sprintf_s(buffer, "%s %s (build %s)", sysInfo.ProductName, sysInfo.DisplayVersion, build);
			return buffer;
		}
		if (sysInfo.ProductName[0] != '\0') {
			char buffer[256]{};
			sprintf_s(buffer, "%s (build %s)", sysInfo.ProductName, build);
			return buffer;
		}
		if (sysInfo.DisplayVersion[0] != '\0') {
			char buffer[256]{};
			sprintf_s(buffer, "%s (build %s)", sysInfo.DisplayVersion, build);
			return buffer;
		}
		return build;
	}

	std::string GetCpuName() {
		HKEY hKey;
		if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
			char buffer[128];
			DWORD bufferSize = sizeof(buffer);
			if (RegQueryValueExA(hKey, "ProcessorNameString", nullptr, nullptr, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
				RegCloseKey(hKey);
				return std::string(buffer);
			}
			RegCloseKey(hKey);
		}
		return "Unknown CPU";
	}

	std::string GetGpuName() {
		IDXGIFactory* factory = nullptr;
		if (SUCCEEDED(CreateDXGIFactory(__uuidof(IDXGIFactory), (void**)&factory))) {
			IDXGIAdapter* adapter = nullptr;
			if (factory->EnumAdapters(0, &adapter) != DXGI_ERROR_NOT_FOUND) {
				DXGI_ADAPTER_DESC desc;
				if (SUCCEEDED(adapter->GetDesc(&desc))) {
					char buffer[128];
					size_t converted = 0;
					wcstombs_s(&converted, buffer, sizeof(buffer), desc.Description, _TRUNCATE);
					adapter->Release();
					factory->Release();
					return std::string(buffer);
				}
				adapter->Release();
			}
			factory->Release();
		}
		return "Unknown GPU";
	}

	std::string GetRamSize() {
		MEMORYSTATUSEX statex;
		statex.dwLength = sizeof(statex);
		if (GlobalMemoryStatusEx(&statex)) {
			double gb = (double)statex.ullTotalPhys / (1024.0 * 1024.0 * 1024.0);
			char buffer[32];
			sprintf_s(buffer, "%.1f GB", gb);
			return std::string(buffer);
		}
		return "Unknown RAM";
	}

	std::string GetUptimeString() {
		ULONGLONG ticks = GetTickCount64();
		ULONG seconds = (ULONG)(ticks / 1000);
		ULONG days = seconds / 86400;
		seconds %= 86400;
		ULONG hours = seconds / 3600;
		seconds %= 3600;
		ULONG minutes = seconds / 60;
		seconds %= 60;
		char buffer[64];
		if (days > 0)
			sprintf_s(buffer, "%ud %02uh %02um %02us", days, hours, minutes, seconds);
		else if (hours > 0)
			sprintf_s(buffer, "%02uh %02um %02us", hours, minutes, seconds);
		else
			sprintf_s(buffer, "%02um %02us", minutes, seconds);
		return std::string(buffer);
	}

	std::string GetUptimeString(uint64_t secondsTotal) {
		ULONG seconds = static_cast<ULONG>(secondsTotal);
		ULONG days = seconds / 86400;
		seconds %= 86400;
		ULONG hours = seconds / 3600;
		seconds %= 3600;
		ULONG minutes = seconds / 60;
		seconds %= 60;
		char buffer[64];
		if (days > 0)
			sprintf_s(buffer, "%ud %02uh %02um %02us", days, hours, minutes, seconds);
		else if (hours > 0)
			sprintf_s(buffer, "%02uh %02um %02us", hours, minutes, seconds);
		else
			sprintf_s(buffer, "%02um %02us", minutes, seconds);
		return std::string(buffer);
	}

	std::string FormatRamSize(uint64_t totalPhysicalBytes) {
		if (totalPhysicalBytes == 0)
			return "Unknown RAM";
		double gb = static_cast<double>(totalPhysicalBytes) / (1024.0 * 1024.0 * 1024.0);
		char buffer[32];
		sprintf_s(buffer, "%.1f GB", gb);
		return buffer;
	}
}

struct ScrollingBuffer {
	int MaxSize;
	int Offset;
	ImVector<ImVec2> Data;
	ScrollingBuffer(int max_size = 2000) {
		MaxSize = max_size;
		Offset = 0;
		Data.reserve(MaxSize);
	}
	void AddPoint(float x, float y) {
		if (Data.size() < MaxSize)
			Data.push_back(ImVec2(x, y));
		else {
			Data[Offset] = ImVec2(x, y);
			Offset = (Offset + 1) % MaxSize;
		}
	}
	void Erase() {
		if (Data.size() > 0) {
			Data.shrink(0);
			Offset = 0;
		}
	}
};

namespace {
	class GpuUsageSampler {
	public:
		float Sample() {
			if (!_initialized)
				Initialize();
			if (!_initialized || _disabled)
				return 0.0f;

			if (ERROR_SUCCESS != ::PdhCollectQueryData(_query))
				return 0.0f;

			DWORD bufferSize = 0;
			DWORD itemCount = 0;
			auto status = ::PdhGetFormattedCounterArrayW(_counter, PDH_FMT_DOUBLE, &bufferSize, &itemCount, nullptr);
			if (status != PDH_MORE_DATA || bufferSize == 0)
				return 0.0f;

			std::vector<BYTE> buffer(bufferSize);
			auto items = reinterpret_cast<PPDH_FMT_COUNTERVALUE_ITEM_W>(buffer.data());
			status = ::PdhGetFormattedCounterArrayW(_counter, PDH_FMT_DOUBLE, &bufferSize, &itemCount, items);
			if (status != ERROR_SUCCESS)
				return 0.0f;

			double total = 0.0;
			for (DWORD i = 0; i < itemCount; i++) {
				if (items[i].FmtValue.CStatus == ERROR_SUCCESS)
					total += items[i].FmtValue.doubleValue;
			}
			if (total < 0.0)
				total = 0.0;
			if (total > 100.0)
				total = 100.0;
			return static_cast<float>(total);
		}

		~GpuUsageSampler() {
			if (_query)
				::PdhCloseQuery(_query);
		}

	private:
		void Initialize() {
			if (ERROR_SUCCESS != ::PdhOpenQueryW(nullptr, 0, &_query))
				return;

			if (ERROR_SUCCESS != ::PdhAddEnglishCounterW(_query, L"\\GPU Engine(*)\\Utilization Percentage", 0, &_counter)) {
				::PdhCloseQuery(_query);
				_query = nullptr;
				_disabled = true;
				return;
			}

			::PdhCollectQueryData(_query);
			_initialized = true;
		}

	private:
		PDH_HQUERY _query{ nullptr };
		PDH_HCOUNTER _counter{ nullptr };
		bool _initialized{ false };
		bool _disabled{ false };
	};

	class NetworkUsageSampler {
	public:
		float SampleMbps() {
			MIB_IFTABLE* table = nullptr;
			ULONG size = 0;
			if (::GetIfTable(nullptr, &size, FALSE) != ERROR_INSUFFICIENT_BUFFER || size == 0)
				return 0.0f;

			std::vector<BYTE> buffer(size);
			table = reinterpret_cast<MIB_IFTABLE*>(buffer.data());
			if (::GetIfTable(table, &size, FALSE) != NO_ERROR)
				return 0.0f;

			ULONGLONG totalBytes = 0;
			for (DWORD i = 0; i < table->dwNumEntries; i++) {
				const auto& row = table->table[i];
				if (row.dwType == IF_TYPE_SOFTWARE_LOOPBACK)
					continue;
				totalBytes += row.dwInOctets;
				totalBytes += row.dwOutOctets;
			}

			auto now = ::GetTickCount64();
			if (_lastTick == 0) {
				_lastTick = now;
				_lastBytes = totalBytes;
				return 0.0f;
			}

			auto elapsedMs = now - _lastTick;
			if (elapsedMs == 0)
				return _lastMbps;

			// Handle 32-bit counter wrapping: dwInOctets/dwOutOctets are DWORD.
			// When the sum wraps, treat the delta as the wrapped-around distance
			// rather than dropping to zero.
			ULONGLONG deltaBytes;
			if (totalBytes >= _lastBytes) {
				deltaBytes = totalBytes - _lastBytes;
			}
			else {
				// Counter(s) wrapped around — estimate the forward delta.
				// Each DWORD counter wraps at 0xFFFFFFFF; with multiple interfaces
				// the sum can wrap at multiples of that, but the simple 64-bit
				// unsigned wrap gives a reasonable one-sample approximation.
				deltaBytes = totalBytes + (ULLONG_MAX - _lastBytes) + 1;
			}

			// Sanity-clamp: if the delta implies > 100 Gbps it's almost certainly
			// a wrap artefact across many interfaces — just keep the last value.
			const double bytesPerSecond = (static_cast<double>(deltaBytes) * 1000.0) / static_cast<double>(elapsedMs);
			if (bytesPerSecond > 12.5e9) {
				_lastTick = now;
				_lastBytes = totalBytes;
				return _lastMbps;
			}

			_lastTick = now;
			_lastBytes = totalBytes;
			_lastMbps = static_cast<float>((bytesPerSecond * 8.0) / (1024.0 * 1024.0));
			return _lastMbps;
		}

	private:
		ULONGLONG _lastBytes{ 0 };
		ULONGLONG _lastTick{ 0 };
		float _lastMbps{ 0.0f };
	};

	void PlotMetric(const char* id, const char* label, const char* desc, ScrollingBuffer& data, float currentValue, float yMax, const ImVec2& size, const ImVec4& color, const char* valueText, float currentTime) {
		ImGui::TextUnformatted(label);
		ImGui::SameLine();
		// Use normal text color on light backgrounds — near-white is invisible there
		const ImVec4& bgCol = ImGui::GetStyle().Colors[ImGuiCol_WindowBg];
		const float lum = bgCol.x * 0.299f + bgCol.y * 0.587f + bgCol.z * 0.114f;
		const bool lightTheme = lum > 0.5f;
		const ImVec4 valueColor = lightTheme
			? ImGui::GetStyleColorVec4(ImGuiCol_Text)          // light: use normal text color
			: ImVec4(0.85f, 0.85f, 0.85f, 1.0f);              // dark: bright off-white
		ImGui::TextColored(valueColor, "%s", valueText);
		if (desc && desc[0] != '\0') {
			float textWidth = ImGui::CalcTextSize(desc).x;
			float availWidth = ImGui::GetContentRegionAvail().x;
			if (availWidth > textWidth + 100.0f) {
				ImGui::SameLine(availWidth - textWidth);
				ImGui::TextDisabled("%s", desc);
			}
		}
		if (ImPlot::BeginPlot(id, size)) {
			ImPlot::SetupAxes(nullptr, nullptr, ImPlotAxisFlags_NoTickLabels, ImPlotAxisFlags_None);
			ImPlot::SetupAxisLimits(ImAxis_X1, currentTime - 30.0f, currentTime, ImGuiCond_Always);
			ImPlot::SetupAxisLimits(ImAxis_Y1, 0, yMax, ImGuiCond_Always);
			ImPlot::SetNextFillStyle(ImColor(color), 0.25f);
			if (data.Data.size() > 0)
				ImPlot::PlotLine(label, &data.Data[0].x, &data.Data[0].y, data.Data.size(), ImPlotLineFlags_Shaded, data.Offset, 2 * sizeof(float));
			ImPlot::EndPlot();
		}
		UNREFERENCED_PARAMETER(currentValue);
	}
}

float PerformanceView::CalculateCPULoad(unsigned long long idleTicks, unsigned long long totalTicks)
{
	static unsigned long long _previousTotalTicks = 0;
	static unsigned long long _previousIdleTicks = 0;

	unsigned long long totalTicksSinceLastTime = totalTicks - _previousTotalTicks;
	unsigned long long idleTicksSinceLastTime = idleTicks - _previousIdleTicks;

	float ret = 1.0f - ((totalTicksSinceLastTime > 0) ? ((float)idleTicksSinceLastTime) / totalTicksSinceLastTime : 0);

	_previousTotalTicks = totalTicks;
	_previousIdleTicks = idleTicks;
	return ret;
}

// Returns 1.0f for "CPU fully pinned", 0.0f for "CPU idle", or somewhere in between
// You'll need to call this at regular intervals, since it measures the load between
// the previous call and the current one.  Returns -1.0 on error.
float PerformanceView::GetCPULoad()
{
	FILETIME idleTime, kernelTime, userTime;
	return GetSystemTimes(&idleTime, &kernelTime, &userTime) ? PerformanceView::CalculateCPULoad(
		PerformanceView::FileTimeToInt64(idleTime),
		PerformanceView::FileTimeToInt64(kernelTime) +
		PerformanceView::FileTimeToInt64(userTime)) : -1.0f;
}

float cpu_load = PerformanceView::GetCPULoad() * 100.0f;
float ram_usage = 0.0f;
float gpu_usage = 0.0f;
float network_usage = 0.0f;
float maxval = 1.0f;

void PerformanceView::RenderPerfWindow(bool compact) {
	if (RemoteClient::IsConnected()) {
		static ScrollingBuffer remoteCpuData, remoteRamData, remoteGpuData, remoteNetworkData;
		static PerformanceSnapshotNet snapshot{};
		static float remoteCpu = 0.0f, remoteRam = 0.0f, remoteGpu = 0.0f, remoteNetwork = 0.0f;
		static float remoteT = 0.0f;
		static float remoteMax = 1.0f;

		remoteT += ImGui::GetIO().DeltaTime;
		if (remoteT < 1.0f) {
			remoteCpuData.AddPoint(remoteT, remoteCpu);
			remoteRamData.AddPoint(remoteT, remoteRam);
			remoteGpuData.AddPoint(remoteT, remoteGpu);
			remoteNetworkData.AddPoint(remoteT, remoteNetwork);
		}

		if (remoteT > remoteMax) {
			PerformanceSnapshotNet latest{};
			if (RemoteClient::GetPerformanceSnapshot(latest))
				snapshot = latest;
			remoteCpu = snapshot.CpuUsage;
			remoteRam = snapshot.MemoryUsage;
			remoteGpu = snapshot.GpuUsage;
			remoteNetwork = snapshot.NetworkMbps;
			remoteCpuData.AddPoint(remoteT, remoteCpu);
			remoteRamData.AddPoint(remoteT, remoteRam);
			remoteGpuData.AddPoint(remoteT, remoteGpu);
			remoteNetworkData.AddPoint(remoteT, remoteNetwork);
			remoteMax += 1.0f;
		}

		const auto& sysInfo = Globals::Get().GetRemoteSysInfo();
		const auto version = FormatRemoteWindowsVersion(sysInfo);
		const auto cpuName = snapshot.CpuName[0] ? std::string(snapshot.CpuName) : std::string("Remote CPU");
		const auto gpuName = snapshot.GpuName[0] ? std::string(snapshot.GpuName) : std::string("Remote GPU");
		const auto ramSize = FormatRamSize(snapshot.TotalPhysicalBytes);
		const float networkMax = (std::max)(10.0f, remoteNetwork * 1.25f);
		char cpuLabel[32]{}, ramLabel[32]{}, gpuLabel[32]{}, netLabel[32]{};
		sprintf_s(cpuLabel, "%.1f%%", remoteCpu);
		sprintf_s(ramLabel, "%.1f%%", remoteRam);
		sprintf_s(gpuLabel, "%.1f%%", remoteGpu);
		sprintf_s(netLabel, "%.2f Mbps", remoteNetwork);

		ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.5f, 1.0f), "Remote: %s", RemoteClient::GetConnectedAddress());
		ImGui::SameLine();
		ImGui::TextDisabled("|");
		ImGui::SameLine();
		ImGui::Text("Windows: %s", version.c_str());

		const float availableHeight = ImGui::GetContentRegionAvail().y;
		const float spacingY = ImGui::GetStyle().ItemSpacing.y;
		const float summaryHeight = ImGui::GetTextLineHeightWithSpacing();
		const float targetGraphHeight = compact ? 62.0f : 90.0f;
		float graphHeight = targetGraphHeight;
		if (availableHeight > 0.0f) {
			const float maxGraphHeight = (availableHeight - summaryHeight - spacingY * 3.0f) * 0.5f;
			graphHeight = (std::max)(60.0f, (std::min)(targetGraphHeight, maxGraphHeight));
		}

		if (ImGui::BeginTable("##RemotePerformanceGrid", 2, ImGuiTableFlags_None)) {
			ImGui::TableSetupColumn("LeftMetric", ImGuiTableColumnFlags_WidthStretch);
			ImGui::TableSetupColumn("RightMetric", ImGuiTableColumnFlags_WidthStretch);
			ImGui::TableNextRow();
			ImGui::TableNextColumn();
			ImVec2 graphSize((std::max)(120.0f, ImGui::GetContentRegionAvail().x), graphHeight);
			PlotMetric("##RemoteCPU", "CPU", cpuName.c_str(), remoteCpuData, remoteCpu, 100.0f, graphSize, ImVec4(0.20f, 0.66f, 0.64f, 1.0f), cpuLabel, remoteT);
			ImGui::TableNextColumn();
			graphSize = ImVec2((std::max)(120.0f, ImGui::GetContentRegionAvail().x), graphHeight);
			PlotMetric("##RemoteRAM", "RAM", ramSize.c_str(), remoteRamData, remoteRam, 100.0f, graphSize, ImVec4(0.52f, 0.20f, 0.66f, 1.0f), ramLabel, remoteT);
			ImGui::TableNextRow();
			ImGui::TableNextColumn();
			graphSize = ImVec2((std::max)(120.0f, ImGui::GetContentRegionAvail().x), graphHeight);
			PlotMetric("##RemoteGPU", "GPU", gpuName.c_str(), remoteGpuData, remoteGpu, 100.0f, graphSize, ImVec4(0.85f, 0.50f, 0.18f, 1.0f), gpuLabel, remoteT);
			ImGui::TableNextColumn();
			graphSize = ImVec2((std::max)(120.0f, ImGui::GetContentRegionAvail().x), graphHeight);
			PlotMetric("##RemoteNET", "NET", "", remoteNetworkData, remoteNetwork, networkMax, graphSize, ImVec4(0.24f, 0.45f, 0.80f, 1.0f), netLabel, remoteT);
			ImGui::EndTable();
		}

		if (compact) {
			ImGui::Text("CPU %.1f%%   RAM %.1f%%   GPU %.1f%%   NET %.2f Mbps", remoteCpu, remoteRam, remoteGpu, remoteNetwork);
		}
		else {
			ImGui::TextDisabled("Remote uptime:");
			ImGui::SameLine();
			ImGui::TextColored(ImVec4(0.40f, 0.85f, 1.0f, 1.0f), "%s", GetUptimeString(snapshot.UptimeSeconds).c_str());
		}
		return;
	}

	static ScrollingBuffer cpuData, ramData, gpuData, networkData;
	static GpuUsageSampler gpuSampler;
	static NetworkUsageSampler networkSampler;
	MEMORYSTATUSEX statex;

	static std::string cpuName = GetCpuName();
	static std::string gpuName = GetGpuName();
	static std::string ramSize = GetRamSize();

	static float t = 0;
	t += ImGui::GetIO().DeltaTime;
	if (t < 1.0f) {
		cpuData.AddPoint(t, cpu_load);
		ramData.AddPoint(t, ram_usage);
		gpuData.AddPoint(t, gpu_usage);
		networkData.AddPoint(t, network_usage);
	}

	if (t > maxval) {
		cpu_load = PerformanceView::GetCPULoad() * 100;
		statex.dwLength = sizeof(statex);
		GlobalMemoryStatusEx(&statex);
		ram_usage = static_cast<float>(statex.dwMemoryLoad);
		gpu_usage = gpuSampler.Sample();
		network_usage = networkSampler.SampleMbps();
		cpuData.AddPoint(t, cpu_load);
		ramData.AddPoint(t, ram_usage);
		gpuData.AddPoint(t, gpu_usage);
		networkData.AddPoint(t, network_usage);
		maxval += 1.0f;
	}

	const float availableHeight = ImGui::GetContentRegionAvail().y;
	const float spacingX = ImGui::GetStyle().ItemSpacing.x;
	const float spacingY = ImGui::GetStyle().ItemSpacing.y;
	const float summaryHeight = ImGui::GetTextLineHeightWithSpacing();
	const float targetGraphHeight = compact ? 62.0f : 90.0f;
	float graphHeight = targetGraphHeight;
	if (availableHeight > 0.0f) {
		const float maxGraphHeight = (availableHeight - summaryHeight - spacingY * 3.0f) * 0.5f;
		graphHeight = (std::max)(60.0f, (std::min)(targetGraphHeight, maxGraphHeight));
	}
	const float networkMax = (std::max)(10.0f, network_usage * 1.25f);
	char cpuLabel[32]{};
	char ramLabel[32]{};
	char gpuLabel[32]{};
	char netLabel[32]{};
	sprintf_s(cpuLabel, "%.1f%%", cpu_load);
	sprintf_s(ramLabel, "%.1f%%", ram_usage);
	sprintf_s(gpuLabel, "%.1f%%", gpu_usage);
	sprintf_s(netLabel, "%.2f Mbps", network_usage);

	if (ImGui::BeginTable("##PerformanceGrid", 2, ImGuiTableFlags_None)) {
		ImGui::TableSetupColumn("LeftMetric", ImGuiTableColumnFlags_WidthStretch);
		ImGui::TableSetupColumn("RightMetric", ImGuiTableColumnFlags_WidthStretch);
		ImGui::TableNextRow();
		ImGui::TableNextColumn();
		ImVec2 graphSize((std::max)(120.0f, ImGui::GetContentRegionAvail().x), graphHeight);
		PlotMetric("##CPU Load", "CPU", cpuName.c_str(), cpuData, cpu_load, 100.0f, graphSize, ImVec4(0.20f, 0.66f, 0.64f, 1.0f), cpuLabel, t);
		ImGui::TableNextColumn();
		graphSize = ImVec2((std::max)(120.0f, ImGui::GetContentRegionAvail().x), graphHeight);
		PlotMetric("##RAM Usage", "RAM", ramSize.c_str(), ramData, ram_usage, 100.0f, graphSize, ImVec4(0.52f, 0.20f, 0.66f, 1.0f), ramLabel, t);

		ImGui::TableNextRow();
		ImGui::TableNextColumn();
		graphSize = ImVec2((std::max)(120.0f, ImGui::GetContentRegionAvail().x), graphHeight);
		PlotMetric("##GPU Usage", "GPU", gpuName.c_str(), gpuData, gpu_usage, 100.0f, graphSize, ImVec4(0.85f, 0.50f, 0.18f, 1.0f), gpuLabel, t);
		ImGui::TableNextColumn();
		graphSize = ImVec2((std::max)(120.0f, ImGui::GetContentRegionAvail().x), graphHeight);
		PlotMetric("##Network Usage", "NET", "", networkData, network_usage, networkMax, graphSize, ImVec4(0.24f, 0.45f, 0.80f, 1.0f), netLabel, t);
		ImGui::EndTable();
	}

	if (compact) {
		ImGui::Text("CPU %.1f%%   RAM %.1f%%   GPU %.1f%%   NET %.2f Mbps", cpu_load, ram_usage, gpu_usage, network_usage);
	}
	else {
		ImGui::TextDisabled("Time to next BSOD:");
		ImGui::SameLine();
		const ImVec4& bgCol2 = ImGui::GetStyle().Colors[ImGuiCol_WindowBg];
		const float lum2 = bgCol2.x * 0.299f + bgCol2.y * 0.587f + bgCol2.z * 0.114f;
		const ImVec4 uptimeColor = (lum2 > 0.5f)
			? ImVec4(0.75f, 0.10f, 0.10f, 1.0f)   // light: deep red
			: ImVec4(1.0f,  0.40f, 0.40f, 1.0f);  // dark: soft coral
		ImGui::TextColored(uptimeColor, "-%s", GetUptimeString().c_str());
	}
}
