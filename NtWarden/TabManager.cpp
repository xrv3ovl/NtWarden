#include "pch.h"
#include "TabManager.h"
#include "Globals.h"
#include "ImGuiExt.h"
#include "imgui_internal.h"
#include "LoggerView.h"
#include "DriverHelper.h"
#include "RemoteClient.h"
#include "Callbacks.h"

#include "SecurityHelper.h"
#include "PerformanceView.h"
#include "Utils.h"
#include <format>
#include <wincodec.h>
#include <WICTextureLoader.h>

extern ID3D11Device* g_pd3dDevice;

using namespace ImGui;
bool driver_check = true;

namespace {
	CStringA FormatProtocolVersion(USHORT version) {
		CStringA text;
		text.Format("%u.%u", (version >> 8) & 0xFF, version & 0xFF);
		return text;
	}

	std::string FormatRemoteWindowsVersion(const SysInfoNet& sysInfo) {
		auto build = std::format("{}.{}.{}.{}", sysInfo.MajorVersion, sysInfo.MinorVersion, sysInfo.BuildNumber, sysInfo.Revision);
		if (sysInfo.ProductName[0] != '\0' && sysInfo.DisplayVersion[0] != '\0')
			return std::format("{} {} (build {})", sysInfo.ProductName, sysInfo.DisplayVersion, build);
		if (sysInfo.ProductName[0] != '\0')
			return std::format("{} (build {})", sysInfo.ProductName, build);
		if (sysInfo.DisplayVersion[0] != '\0')
			return std::format("{} (build {})", sysInfo.DisplayVersion, build);
		return build;
	}

	void RenderRemoteUnavailable(const char* feature, const char* detail = nullptr) {
		ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.5f, 1.0f), "Remote: %s", RemoteClient::GetConnectedAddress());
		ImGui::Separator();
		ImGui::TextWrapped("%s is not available over the current remote protocol.", feature);
		if (detail && detail[0] != '\0')
			ImGui::TextDisabled("%s", detail);
		ImGui::TextDisabled("Local machine data is hidden while a remote client is connected.");
	}
}

void TabManager::LogDriverFailure(const char* prefix) {
	auto error = Utils::WideToUtf8(DriverHelper::GetLastErrorText());
	LoggerView::AddLog(LoggerView::UserModeLog, "%s: %s", prefix, error.empty() ? "Unknown error" : error.c_str());
}

void TabManager::PumpKernelLogs() {
	std::vector<KERNEL_LOG_ENTRY> entries;
	unsigned long nextSequence = _nextKernelLogSequence;
	auto now = std::chrono::steady_clock::now();

	if (RemoteClient::IsConnected())
	{
		_nextKernelLogSequence = 0;
		_lastKernelLogSequenceSeen = 0;
		return;
	}
	if (!DriverHelper::IsDriverLoaded())
	{
		_nextKernelLogSequence = 0;
		_lastKernelLogSequenceSeen = 0;
		return;
	}
	if (_lastKernelLogPoll.time_since_epoch().count() != 0 &&
		now - _lastKernelLogPoll < std::chrono::milliseconds(250))
		return;

	_lastKernelLogPoll = now;
	if (!DriverHelper::QueryKernelLogs(_nextKernelLogSequence, entries, nextSequence))
		return;

	if (nextSequence < _nextKernelLogSequence) {
		_nextKernelLogSequence = 0;
		return;
	}

	for (const auto& entry : entries) {
		if (entry.Text[0] == '\0')
			continue;
		if (entry.Sequence != 0 && entry.Sequence <= _lastKernelLogSequenceSeen)
			continue;
		LoggerView::AddLog(LoggerView::KernelModeLog, "%s", entry.Text);
		if (entry.Sequence > _lastKernelLogSequenceSeen)
			_lastKernelLogSequenceSeen = entry.Sequence;
	}

	_nextKernelLogSequence = nextSequence;
}


TabManager::TabManager() {
	_buildInfo = WindowsVersionDetector::Detect();
	_procView = std::make_unique<ProcessesView>();
	_svcView = std::make_unique<ServicesView>();
	_modView = std::make_unique<ModulesView>();
	_etwView = std::make_unique<ETWView>();
	_netView = std::make_unique<NetworkView>();

	_rootCertView = std::make_unique<RootCertificatesView>();
	_registryView = std::make_unique<RegistryView>();
	_ndisView = std::make_unique<NdisView>();
	_symbolView = std::make_unique<SymbolView>();
	_miniFilterView = std::make_unique<MiniFilterView>();
	_processObjectsView = std::make_unique<ProcessObjectsView>();
	_kernelMemoryView = std::make_unique<KernelMemoryView>();
	_objectManagerView = std::make_unique<ObjectManagerView>();
	_kernelTimersView = std::make_unique<KernelTimersView>();
	_kernelHooksView = std::make_unique<KernelHooksView>();
	_ipcView = std::make_unique<IPCView>();
	_gdtIdtView = std::make_unique<GdtIdtView>();
	_irpDispatchView = std::make_unique<IrpDispatchView>();
	_wfpView = std::make_unique<WfpView>();

	_processSecurityView = std::make_unique<ProcessSecurityView>();
	_dseStatusView = std::make_unique<DseStatusView>();
	_ciPolicyView = std::make_unique<CiPolicyView>();
	_kernelIntegrityView = std::make_unique<KernelIntegrityView>();
	_hypervisorHookView = std::make_unique<HypervisorHookView>();
	_memoryView = std::make_unique<MemoryView>();

}

bool TabManager::IsPerformanceOverlayEnabled() const {
	return _performanceOverlayEnabled;
}

void TabManager::BuildTabs() {
	if (_remoteConnectPending && _remoteConnectFuture.valid() &&
		_remoteConnectFuture.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
		bool success = _remoteConnectFuture.get();
		_remoteConnectPending = false;
		if (success) {
			Globals::Get().SetRemoteMode(true);
			Globals::Get().SetRemoteAddress(std::string(_remoteIP) + ":" + std::to_string(_remotePort));
			LoggerView::AddLog(LoggerView::UserModeLog, "Connected to %s:%d", _remoteIP, _remotePort);
		}
		else {
			LoggerView::AddLog(LoggerView::UserModeLog, "Failed to connect to %s:%d", _remoteIP, _remotePort);
		}
	}

	PumpKernelLogs();

	static bool opt_fullscreen = true;
	static bool opt_padding = false;
	static ImGuiDockNodeFlags dockspace_flags = ImGuiDockNodeFlags_None;

	// We are using the ImGuiWindowFlags_NoDocking flag to make the parent window not dockable into,
	// because it would be confusing to have two docking targets within each others.
	ImGuiWindowFlags window_flags = ImGuiWindowFlags_NoDocking;
	const ImGuiViewport* viewport = ImGui::GetMainViewport();
	ImGui::SetNextWindowPos(viewport->WorkPos);
	ImGui::SetNextWindowSize(viewport->WorkSize);
	ImGui::SetNextWindowViewport(viewport->ID);
	ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
	ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
	window_flags |= ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove;
	window_flags |= ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNavFocus;

	// When using ImGuiDockNodeFlags_PassthruCentralNode, DockSpace() will render our background
	// and handle the pass-thru hole, so we ask Begin() to not render a background.
	if (dockspace_flags & ImGuiDockNodeFlags_PassthruCentralNode)
		window_flags |= ImGuiWindowFlags_NoBackground;

	// Important: note that we proceed even if Begin() returns false (aka window is collapsed).
	// This is because we want to keep our DockSpace() active. If a DockSpace() is inactive,
	// all active windows docked into it will lose their parent and become undocked.
	// We cannot preserve the docking relationship between an active window and an inactive docking, otherwise
	// any change of dockspace/settings would lead to windows being stuck in limbo and never being visible.
	if (!opt_padding)
		ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));

	ImGui::Begin("NtWardenDockSpace", nullptr, window_flags);
	if (!opt_padding)
		ImGui::PopStyleVar();

	if (opt_fullscreen)
		ImGui::PopStyleVar(2);

	// Submit the DockSpace
	ImGuiIO& io = ImGui::GetIO();
	if (io.ConfigFlags & ImGuiConfigFlags_DockingEnable)
	{
		ImGuiID dockspace_id = ImGui::GetID("NtWardenDockSpace");
		ImGui::DockSpace(dockspace_id, ImVec2(0.0f, 0.0f), dockspace_flags);

		static auto first_time = true;
		if (first_time)
		{
			first_time = false;

			ImGui::DockBuilderRemoveNode(dockspace_id); // clear any previous layout
			ImGui::DockBuilderAddNode(dockspace_id, dockspace_flags | ImGuiDockNodeFlags_DockSpace);
			ImGui::DockBuilderSetNodeSize(dockspace_id, viewport->Size);

			auto dock_id_down = ImGui::DockBuilderSplitNode(dockspace_id, ImGuiDir_Down, 0.28f, nullptr, &dockspace_id);
			auto dock_id_perf = ImGui::DockBuilderSplitNode(dock_id_down, ImGuiDir_Right, 0.36f, nullptr, &dock_id_down);

			ImGui::DockBuilderDockWindow("Explorer", dockspace_id);
			ImGui::DockBuilderDockWindow("Logger", dock_id_down);
			ImGui::DockBuilderDockWindow("Performance", dock_id_perf);
			if (auto node = ImGui::DockBuilderGetNode(dockspace_id))
				node->LocalFlags |= ImGuiDockNodeFlags_NoTabBar;
			ImGui::DockBuilderFinish(dockspace_id);

		}
	}

	BuildMainMenu();
	//Enable following code to make Processes window TOPMOST
	//ImGuiWindowClass topmost;
	//topmost.ClassId = ImHashStr("TopMost");
	//topmost.ViewportFlagsOverrideSet = ImGuiViewportFlags_TopMost;
	//ImGui::SetNextWindowClass(&topmost);
	ImGui::SetNextWindowBgAlpha(0.6f);
	ImGui::SetNextWindowSizeConstraints(ImVec2(860, 520), ImVec2(FLT_MAX, FLT_MAX));

	BuildMainModeWindow();

	ImGui::SetNextWindowSizeConstraints(ImVec2(320, 180), ImVec2(FLT_MAX, FLT_MAX));
	if (ImGui::Begin("Logger")) {
		LoggerView::RenderLogWindow();
	}
	ImGui::End();

	if (_performanceOverlayEnabled) {
		BuildPerformanceOverlay();
	}
	else {
		ImGui::SetNextWindowBgAlpha(0.6f);
		ImGui::SetNextWindowSizeConstraints(ImVec2(520, 240), ImVec2(FLT_MAX, FLT_MAX));
		if (ImGui::Begin("Performance")) {
			PerformanceView::RenderPerfWindow(false);
		}
		ImGui::End();
	}

	static auto first_time = true;
	if (first_time)
	{
		first_time = false;
		ImGui::SetWindowFocus("System Details");
	}
	//End of Dockspace
	ImGui::End();
}

void TabManager::BuildPerformanceOverlay() {
	ImGuiWindowClass topmost;
	topmost.ClassId = ImHashStr("PerformanceOverlayClass");
	topmost.ParentViewportId = 0;
	topmost.ViewportFlagsOverrideSet = ImGuiViewportFlags_TopMost | ImGuiViewportFlags_NoTaskBarIcon | ImGuiViewportFlags_NoAutoMerge;
	ImGui::SetNextWindowClass(&topmost);

	const auto* viewport = ImGui::GetMainViewport();
	ImGui::SetNextWindowBgAlpha(_performanceOverlayAlpha);
	ImGui::SetNextWindowPos(ImVec2(viewport->WorkPos.x + viewport->WorkSize.x - 560.0f, viewport->WorkPos.y + 48.0f), ImGuiCond_FirstUseEver);
	ImGui::SetNextWindowSize(_performanceOverlayCompact ? ImVec2(540.0f, 250.0f) : ImVec2(620.0f, 320.0f), ImGuiCond_FirstUseEver);
	ImGui::SetNextWindowSizeConstraints(ImVec2(460.0f, 210.0f), ImVec2(900.0f, 520.0f));

	ImGuiWindowFlags flags = ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoSavedSettings;
	if (ImGui::Begin("Performance Overlay", &_performanceOverlayEnabled, flags)) {
		PerformanceView::RenderPerfWindow(_performanceOverlayCompact);
		if (ImGui::BeginPopupContextWindow("##PerformanceOverlayContext", ImGuiPopupFlags_MouseButtonRight | ImGuiPopupFlags_NoOpenOverItems)) {
			ImGui::Checkbox("Compact Overlay", &_performanceOverlayCompact);
			ImGui::SliderFloat("Transparency", &_performanceOverlayAlpha, 0.15f, 0.85f, "%.2f");
			ImGui::Separator();
			if (ImGui::MenuItem("Show Main Window")) {
				auto hwnd = Globals::Get().GetMainHwnd();
				::ShowWindow(hwnd, SW_RESTORE);
				::ShowWindow(hwnd, SW_SHOW);
				::SetForegroundWindow(hwnd);
			}
			if (ImGui::MenuItem("Exit NtWarden"))
				::PostQuitMessage(0);
			ImGui::Separator();
			if (ImGui::MenuItem("Disable Overlay"))
				_performanceOverlayEnabled = false;
			ImGui::EndPopup();
		}
	}
	ImGui::End();
}

void TabManager::BuildMainModeWindow() {
	ImGui::SetNextWindowBgAlpha(0.6f);
	if (ImGui::Begin("Explorer")) {
		if (ImGui::BeginTabBar("ModeTabBar")) {
			if (ImGui::BeginTabItem("User Mode")) {
				_showingKernelMode = false;
				BuildUserModeContent();
				ImGui::EndTabItem();
			}
			if (ImGui::BeginTabItem("Kernel Mode")) {
				_showingKernelMode = true;
				BuildKernelModeContent();
				ImGui::EndTabItem();
			}
			ImGui::EndTabBar();
		}
	}
	ImGui::End();
}

	void TabManager::BuildUserModeContent() {
	std::string version;
	if (RemoteClient::IsConnected()) {
		auto sysInfo = Globals::Get().GetRemoteSysInfo();
		version = FormatRemoteWindowsVersion(sysInfo);
	}
	else {
		auto versionText = _buildInfo.VersionString();
		version = Utils::WideToUtf8(versionText.c_str());
	}

	if (ImGui::Button("Refresh##CurrentUserTab")) {
		RefreshCurrentTab();
	}
	ImGui::SameLine();
	ImGui::AlignTextToFramePadding();
	if (RemoteClient::IsConnected()) {
		ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.5f, 1.0f), "Remote: %s", RemoteClient::GetConnectedAddress());
		ImGui::SameLine();
		ImGui::AlignTextToFramePadding();
		ImGui::TextDisabled("|");
		ImGui::SameLine();
		ImGui::AlignTextToFramePadding();
	}
	ImGui::Text("Windows: %s", version.c_str());
	ImGui::SameLine();
	ImGui::AlignTextToFramePadding();
	ImGui::TextDisabled("|");
	ImGui::SameLine();
	ImGui::AlignTextToFramePadding();
	if (RemoteClient::IsConnected())
		ImGui::Text("KWinSys: Remote session");
	else
		ImGui::Text("KWinSys: %s", DriverHelper::IsDriverLoaded() ? "Loaded" : "Not loaded");
	ImGui::SameLine();
	ImGui::TextDisabled("|");
	ImGui::Separator();
	if (ImGui::BeginTabBar("UserModeTabBar")) {
		if (ImGui::BeginTabItem("Processes")) {
			_activeUserTab = "Processes";
			_procView->BuildWindow();
			ImGui::EndTabItem();
		}
		if (ImGui::BeginTabItem("Services")) {
			_activeUserTab = "Services";
			_svcView->BuildWindow();
			ImGui::EndTabItem();
		}
		if (ImGui::BeginTabItem("Network")) {
			_activeUserTab = "Network";
				if (ImGui::BeginTabBar("NetworkTab")) {
					if (ImGui::BeginTabItem("Connections")) {
						_activeUserNetworkTab = "Connections";
						_netView->BuildWindow();
						ImGui::EndTabItem();
					}
if (ImGui::BeginTabItem("Root Certificates")) {
						_activeUserNetworkTab = "Root Certificates";
						_rootCertView->BuildWindow();
						ImGui::EndTabItem();
					}
					if (ImGui::BeginTabItem("NDIS")) {
						_activeUserNetworkTab = "NDIS";
						_ndisView->BuildWindow();
						ImGui::EndTabItem();
					}
				ImGui::EndTabBar();
			}
			ImGui::EndTabItem();
		}
		if (ImGui::BeginTabItem("ETW")) {
			_activeUserTab = "ETW";
			_etwView->BuildWindow();
			ImGui::EndTabItem();
		}
		if (ImGui::BeginTabItem("IPC")) {
			_activeUserTab = "IPC";
			_ipcView->BuildWindow();
			ImGui::EndTabItem();
		}
		if (ImGui::BeginTabItem("Object Manager")) {
			_activeUserTab = "Object Manager";
			_objectManagerView->BuildWindow();
			ImGui::EndTabItem();
		}
		if (ImGui::BeginTabItem("Registry")) {
			_activeUserTab = "Registry";
			_registryView->BuildWindow();
			ImGui::EndTabItem();
		}
if (ImGui::BeginTabItem("Symbols")) {
			_activeUserTab = "Symbols";
			_symbolView->BuildWindow(SymbolScope::User);
			ImGui::EndTabItem();
		}
		ImGui::EndTabBar();
	}
}

void TabManager::BuildKernelModeContent() {
	if (driver_check) {
		if (DriverHelper::IsDriverInstalled()) {
			if (DriverHelper::LoadDriver()) {
				if (DriverHelper::VerifyLoadedDriverVersion())
					LoggerView::AddLog(LoggerView::UserModeLog, "Kernel driver loaded and version verified");
				else
					LogDriverFailure("Kernel driver loaded, but verification failed");
			}
		}
		else if (SecurityHelper::IsRunningElevated()) {
			LoggerView::AddLog(LoggerView::UserModeLog, "Driver not installed. Attempting automatic install...");
			if (DriverHelper::InstallDriver()) {
				LoggerView::AddLog(LoggerView::UserModeLog, "Driver installed successfully");
				if (DriverHelper::LoadDriver()) {
					if (DriverHelper::VerifyLoadedDriverVersion())
						LoggerView::AddLog(LoggerView::UserModeLog, "Kernel driver loaded and version verified");
					else
						LogDriverFailure("Kernel driver loaded, but verification failed");
				}
				else {
					LogDriverFailure("Driver installed but failed to start");
				}
			}
			else {
				LogDriverFailure("Automatic driver installation failed");
			}
		}
		driver_check = false;
	}

	const bool elevated = SecurityHelper::IsRunningElevated();
	const bool driverInstalled = DriverHelper::IsDriverInstalled();
	const bool driverLoaded = DriverHelper::IsDriverLoaded();
	const auto driverVersion = driverLoaded ? DriverHelper::GetVersion() : 0;
	const auto expectedDriverVersion = DriverHelper::GetCurrentVersion();
	const bool driverVersionMismatch = driverLoaded && driverVersion != 0 && driverVersion != expectedDriverVersion;
	const bool driverVersionUnknown = driverLoaded && driverVersion == 0;
	const bool remoteConnected = RemoteClient::IsConnected();
	const char* driverStatus = driverLoaded ? "Running" : (driverInstalled ? "Installed" : "Not installed");
	auto driverVersionText = FormatProtocolVersion(driverVersion);
	auto expectedDriverVersionText = FormatProtocolVersion(expectedDriverVersion);
	if (ImGui::Button("Refresh##CurrentKernelTab"))
		RefreshCurrentTab();
	ImGui::SameLine();
	ImGui::AlignTextToFramePadding();
	if (RemoteClient::IsConnected()) {
		ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.5f, 1.0f), "Remote: %s", RemoteClient::GetConnectedAddress());
	}
	else {
		ImGui::Text("Driver status: %s", driverStatus);
	}
	std::string version;
	if (RemoteClient::IsConnected()) {
		auto sysInfo = Globals::Get().GetRemoteSysInfo();
		version = FormatRemoteWindowsVersion(sysInfo);
	}
	else {
		auto versionText = _buildInfo.VersionString();
		version = Utils::WideToUtf8(versionText.c_str());
	}
	ImGui::SameLine();
	ImGui::AlignTextToFramePadding();
	ImGui::TextDisabled("|");
	ImGui::SameLine();
	ImGui::AlignTextToFramePadding();
	ImGui::Text("Windows: %s", version.c_str());
	ImGui::SameLine();
	ImGui::AlignTextToFramePadding();
	ImGui::TextDisabled("|");
	ImGui::SameLine();
	if (remoteConnected)
		ImGui::AlignTextToFramePadding(),
		ImGui::Text("KWinSys: Remote session");
	else if (driverLoaded && driverVersion != 0)
		ImGui::AlignTextToFramePadding(),
		ImGui::Text("KWinSys: %s", driverVersionText.GetString());
	else if (driverLoaded)
		ImGui::AlignTextToFramePadding(),
		ImGui::Text("KWinSys: Unknown");
	else
		ImGui::AlignTextToFramePadding(),
		ImGui::Text("KWinSys: Not loaded");
	ImGui::Separator();

	static bool loggedMissingDriver = false;
	static bool loggedVersionMismatch = false;
	static bool loggedUnknownVersion = false;
	if (!driverLoaded) {
		if (!loggedMissingDriver) {
			LoggerView::AddLog(LoggerView::UserModeLog, "Kernel inspection is optional. Install and load the driver from the Driver menu to enable kernel-backed tabs.");
			loggedMissingDriver = true;
		}
		loggedVersionMismatch = false;
		loggedUnknownVersion = false;
	}
	else if (driverVersionMismatch) {
		if (!loggedVersionMismatch) {
			LoggerView::AddLog(LoggerView::UserModeLog,
				"Loaded driver is outdated. Found %s, expected %s. Use the Driver menu to update it.",
				driverVersionText.GetString(), expectedDriverVersionText.GetString());
			loggedVersionMismatch = true;
		}
		loggedMissingDriver = false;
		loggedUnknownVersion = false;
	}
	else if (driverVersionUnknown) {
		if (!loggedUnknownVersion) {
			auto error = Utils::WideToUtf8(DriverHelper::GetLastErrorText());
			LoggerView::AddLog(LoggerView::UserModeLog,
				"Loaded driver did not respond to the version query. Use the Driver menu to reinstall or update it.");
			if (!error.empty())
				LoggerView::AddLog(LoggerView::UserModeLog, "Driver version query details: %s", error.c_str());
			loggedUnknownVersion = true;
		}
		loggedMissingDriver = false;
		loggedVersionMismatch = false;
	}
	else {
		loggedMissingDriver = false;
		loggedVersionMismatch = false;
		loggedUnknownVersion = false;
	}

	const bool kernelDriverUsable = driverLoaded && !driverVersionMismatch && !driverVersionUnknown;
	const bool kernelAvailable = kernelDriverUsable || remoteConnected;

	if (ImGui::BeginTabBar("KernelModeTabBar", ImGuiTabBarFlags_FittingPolicyWrap)) {
		if (ImGui::BeginTabItem("Process Objects")) {
			_activeKernelTab = "Process Objects";
			if (kernelAvailable)
				_processObjectsView->BuildWindow();
			else
				ImGui::TextUnformatted("Process object inspection requires a verified driver.");
			ImGui::EndTabItem();
		}
		if (ImGui::BeginTabItem("Modules")) {
			_activeKernelTab = "Modules";
			if (kernelAvailable)
				_modView->BuildWindow();
			else
				ImGui::TextUnformatted("Kernel modules require a verified driver.");
			ImGui::EndTabItem();
		}
		if (ImGui::BeginTabItem("Callbacks")) {
			_activeKernelTab = "Callbacks";
			if (kernelAvailable) {
				Callbacks::RenderCallbackTables();
				ImGui::Spacing();
				ImGui::Separator();
				Callbacks::RenderIntegrityTable();
			}
			else
				ImGui::TextUnformatted("Kernel callbacks require a verified driver.");
			ImGui::EndTabItem();
		}
		if (ImGui::BeginTabItem("SSDT")) {
			_activeKernelTab = "SSDT";
			if (kernelAvailable)
				_kernelHooksView->BuildWindow();
			else
				ImGui::TextUnformatted("SSDT inspection requires a verified driver.");
			ImGui::EndTabItem();
		}
		if (ImGui::BeginTabItem("Symbols")) {
			_activeKernelTab = "Symbols";
			_symbolView->BuildWindow(SymbolScope::Kernel);
			ImGui::EndTabItem();
		}
		if (ImGui::BeginTabItem("Kernel Pool")) {
			_activeKernelTab = "Kernel Pool";
			_kernelMemoryView->BuildWindow();
			ImGui::EndTabItem();
		}
		if (ImGui::BeginTabItem("Memory R/W")) {
			_activeKernelTab = "Memory R/W";
			if (kernelAvailable)
				_memoryView->BuildWindow();
			else
				ImGui::TextUnformatted("Memory inspection requires a verified driver.");
			ImGui::EndTabItem();
		}
if (ImGui::BeginTabItem("Timers")) {
			_activeKernelTab = "Timers";
			_kernelTimersView->BuildWindow();
			ImGui::EndTabItem();
		}
		if (ImGui::BeginTabItem("Filter")) {
			_activeKernelTab = "Filter";
			_miniFilterView->BuildWindow();
			ImGui::EndTabItem();
		}
		if (ImGui::BeginTabItem("Descriptor Tables")) {
			_activeKernelTab = "Descriptor Tables";
			if (kernelAvailable)
				_gdtIdtView->BuildWindow();
			else
				ImGui::TextUnformatted("Descriptor table inspection requires a verified driver.");
			ImGui::EndTabItem();
		}
if (ImGui::BeginTabItem("IRP Dispatch")) {
			_activeKernelTab = "IRP Dispatch";
			if (kernelAvailable)
				_irpDispatchView->BuildWindow();
			else
				ImGui::TextUnformatted("IRP dispatch inspection requires a verified driver.");
			ImGui::EndTabItem();
		}

		if (ImGui::BeginTabItem("WFP")) {
			_activeKernelTab = "WFP";
			if (kernelAvailable)
				_wfpView->BuildWindow();
			else
				ImGui::TextUnformatted("WFP inspection requires a verified driver.");
			ImGui::EndTabItem();
		}
		if (ImGui::BeginTabItem("DSE Status")) {
			_activeKernelTab = "DSE Status";
			_dseStatusView->BuildDsePanel();
			ImGui::EndTabItem();
		}
		if (ImGui::BeginTabItem("CI Policy")) {
			_activeKernelTab = "CI Policy";
			_ciPolicyView->BuildCiPolicyPanel();
			ImGui::EndTabItem();
		}
		if (ImGui::BeginTabItem("Kernel Integrity")) {
			_activeKernelTab = "Kernel Integrity";
			_kernelIntegrityView->BuildKernelIntegrityTable();
			ImGui::EndTabItem();
		}
		if (ImGui::BeginTabItem("Hypervisor Hooks")) {
			_activeKernelTab = "Hypervisor Hooks";
			_hypervisorHookView->BuildHypervisorHookTable();
			ImGui::EndTabItem();
		}
		ImGui::EndTabBar();
	}
}

void TabManager::RefreshCurrentTab() {
	if (_showingKernelMode) {
		if (_activeKernelTab == "Process Objects")
			_processObjectsView->RefreshProcesses();
		else if (_activeKernelTab == "Modules")
			_modView->RefreshNow();
		else if (_activeKernelTab == "Callbacks") {
			Callbacks::Refresh();
			Callbacks::ScanIntegrity();
		}
		else if (_activeKernelTab == "SSDT")
			_kernelHooksView->RefreshNow();
		else if (_activeKernelTab == "Symbols")
			_symbolView->RefreshNow(SymbolScope::Kernel);
		else if (_activeKernelTab == "Kernel Pool")
			_kernelMemoryView->Refresh();
		else if (_activeKernelTab == "Memory R/W")
			_memoryView->RefreshNow();
else if (_activeKernelTab == "Timers")
			_kernelTimersView->Refresh();
		else if (_activeKernelTab == "Filter")
			_miniFilterView->Refresh();
		else if (_activeKernelTab == "Descriptor Tables")
			_gdtIdtView->RefreshNow();
else if (_activeKernelTab == "IRP Dispatch")
			_irpDispatchView->RefreshNow();

		else if (_activeKernelTab == "WFP")
			_wfpView->RefreshNow();
		else if (_activeKernelTab == "DSE Status")
			_dseStatusView->ScanDseStatus();
		else if (_activeKernelTab == "CI Policy")
			_ciPolicyView->ScanCiPolicy();
		else if (_activeKernelTab == "Kernel Integrity")
			_kernelIntegrityView->RefreshNow();
		else if (_activeKernelTab == "Hypervisor Hooks")
			_hypervisorHookView->ScanHypervisorHooks();
	}
	else {
		if (_activeUserTab == "Processes")
			_procView->RefreshNow();
		else if (_activeUserTab == "Services")
			_svcView->RefreshNow();
		else if (_activeUserTab == "Network") {
			if (_activeUserNetworkTab == "Connections")
				_netView->RefreshNow();
			else if (_activeUserNetworkTab == "Root Certificates")
				_rootCertView->RefreshNow();
			else if (_activeUserNetworkTab == "NDIS")
				_ndisView->RefreshNow();
		}
		else if (_activeUserTab == "ETW")
			_etwView->RefreshNow();
		else if (_activeUserTab == "IPC")
			_ipcView->RefreshNow();
		else if (_activeUserTab == "Object Manager")
			_objectManagerView->Refresh();
		else if (_activeUserTab == "Registry")
			_registryView->Refresh();
		else if (_activeUserTab == "Symbols")
			_symbolView->RefreshNow(SymbolScope::User);
	}
}

void TabManager::BuildOptionsMenu() {
	if (BeginMenu("Options")) {
		if (MenuItem("Always On Top", nullptr, &_alwaysOnTop)) {
			::SetWindowPos(Globals::Get().GetMainHwnd(), !_alwaysOnTop ? HWND_NOTOPMOST : HWND_TOPMOST, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);
		}
		Separator();
		if (BeginMenu("Performance Overlay")) {
			if (MenuItem("Enable Overlay", nullptr, _performanceOverlayEnabled))
				_performanceOverlayEnabled = !_performanceOverlayEnabled;
			ImGui::BeginDisabled(!_performanceOverlayEnabled);
			ImGui::Checkbox("Compact Mode", &_performanceOverlayCompact);
			ImGui::SliderFloat("Transparency", &_performanceOverlayAlpha, 0.15f, 0.85f, "%.2f");
			ImGui::EndDisabled();
			ImGui::Separator();
			ImGui::TextDisabled("Overlay is topmost and uses the same");
			ImGui::TextDisabled("existing performance samplers.");
			ImGui::EndMenu();
		}
		Separator();
		if (BeginMenu("Theme")) {
			if (MenuItem("Classic", nullptr, _theme == Theme::Classic)) {
				Utils::ApplyClassicTheme();
				_theme = Theme::Classic;
			}
			if (MenuItem("Light", nullptr, _theme == Theme::Light)) {
				Utils::ApplyLightTheme();
				_theme = Theme::Light;
			}
			if (MenuItem("Dark", nullptr, _theme == Theme::Dark)) {
				Utils::ApplyDarkTheme();
				_theme = Theme::Dark;
			}
			if (MenuItem("Red Samurai", nullptr, _theme == Theme::RedSamurai)) {
				Utils::ApplyRedSamuraiTheme();
				_theme = Theme::RedSamurai;
			}
			if (MenuItem("Neon Blue Green", nullptr, _theme == Theme::NeonBlueGreen)) {
				Utils::ApplyNeonBlueGreenTheme();
				_theme = Theme::NeonBlueGreen;
			}

			ImGui::EndMenu();
		}

		ImGui::EndMenu();
	}
}

void TabManager::BuildDriverMenu() {
	const bool elevated = SecurityHelper::IsRunningElevated();
	const bool installed = DriverHelper::IsDriverInstalled();
	const bool loaded = DriverHelper::IsDriverLoaded();
	const auto driverVersion = loaded ? DriverHelper::GetVersion() : 0;
	const auto expectedDriverVersion = DriverHelper::GetCurrentVersion();

	if (BeginMenu("Driver")) {
		if (MenuItem(installed ? "Reinstall Driver" : "Install Driver")) {
			if (!elevated)
				LoggerView::AddLog(LoggerView::UserModeLog, "Driver install requires elevation");
			else if (DriverHelper::InstallDriver()) {
				if (DriverHelper::LoadDriver() && DriverHelper::VerifyLoadedDriverVersion())
					LoggerView::AddLog(LoggerView::UserModeLog, "Driver installed successfully and version verified");
				else
					LogDriverFailure("Driver installed, but verification failed");
			}
			else {
				LogDriverFailure("Driver install failed");
			}
		}

		if (MenuItem(loaded ? "Stop Driver" : "Load Driver")) {
			if (!installed)
				LoggerView::AddLog(LoggerView::UserModeLog, "Install the driver before trying to load it");
			else if (DriverHelper::LoadDriver(!loaded)) {
				if (loaded) {
					LoggerView::AddLog(LoggerView::UserModeLog, "Driver stopped successfully");
				}
				else if (DriverHelper::VerifyLoadedDriverVersion()) {
					LoggerView::AddLog(LoggerView::UserModeLog, "Driver loaded successfully and version verified");
				}
				else {
					LogDriverFailure("Driver loaded, but verification failed");
				}
			}
			else
				LogDriverFailure("Driver action failed");
		}

		if (MenuItem("Update Driver")) {
			if (!elevated)
				LoggerView::AddLog(LoggerView::UserModeLog, "Driver update requires elevation");
			else if (DriverHelper::UpdateDriver())
				LoggerView::AddLog(LoggerView::UserModeLog, "Driver updated successfully and version verified");
			else
				LogDriverFailure("Driver update failed");
		}

		if (MenuItem("Remove Driver")) {
			if (!elevated)
				LoggerView::AddLog(LoggerView::UserModeLog, "Driver removal requires elevation");
			else if (DriverHelper::RemoveDriver())
				LoggerView::AddLog(LoggerView::UserModeLog, "Driver removed successfully");
			else
				LogDriverFailure("Driver removal failed");
		}

		ImGui::Separator();
		ImGui::TextDisabled("Status: %s", loaded ? "Running" : (installed ? "Installed" : "Not installed"));
		if (loaded) {
			if (driverVersion == 0)
				ImGui::TextDisabled("Version: Unknown");
			else
				ImGui::TextDisabled("Version: %s", FormatProtocolVersion(driverVersion).GetString());
			ImGui::TextDisabled("Expected: %s", FormatProtocolVersion(expectedDriverVersion).GetString());
		}
		ImGui::EndMenu();
	}
}

void TabManager::BuildFileMenu() {
	if (BeginMenu("File")) {
		if (!SecurityHelper::IsRunningElevated()) {
			// Lazily create the shield icon texture once
			static ID3D11ShaderResourceView* s_shieldTexture = nullptr;
			static bool s_shieldAttempted = false;
			if (!s_shieldAttempted) {
				s_shieldAttempted = true;
				HICON hIcon = SecurityHelper::GetShieldIcon();
				if (hIcon && g_pd3dDevice) {
					CComPtr<IWICImagingFactory> factory;
					if (SUCCEEDED(::CoCreateInstance(CLSID_WICImagingFactory, nullptr,
						CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&factory)))) {
						CComPtr<IWICBitmap> bitmap;
						if (SUCCEEDED(factory->CreateBitmapFromHICON(hIcon, &bitmap))) {
							UINT w = 0, h = 0;
							bitmap->GetSize(&w, &h);
							if (w > 0 && h > 0) {
								CComPtr<IWICBitmapLock> lock;
								if (SUCCEEDED(bitmap->Lock(nullptr, WICBitmapLockRead, &lock))) {
									UINT bufSize = 0;
									WICInProcPointer data = nullptr;
									if (SUCCEEDED(lock->GetDataPointer(&bufSize, &data)) && data) {
										D3D11_TEXTURE2D_DESC desc{};
										desc.Width = w;
										desc.Height = h;
										desc.MipLevels = 1;
										desc.ArraySize = 1;
										desc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
										desc.SampleDesc.Count = 1;
										desc.Usage = D3D11_USAGE_DEFAULT;
										desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
										D3D11_SUBRESOURCE_DATA initData{};
										initData.pSysMem = data;
										initData.SysMemPitch = w * 4;
										CComPtr<ID3D11Texture2D> texture;
										if (SUCCEEDED(g_pd3dDevice->CreateTexture2D(&desc, &initData, &texture))) {
											D3D11_SHADER_RESOURCE_VIEW_DESC srvDesc{};
											srvDesc.Format = desc.Format;
											srvDesc.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D;
											srvDesc.Texture2D.MipLevels = 1;
											g_pd3dDevice->CreateShaderResourceView(texture, &srvDesc, &s_shieldTexture);
										}
									}
								}
							}
						}
					}
					::DestroyIcon(hIcon);
				}
			}

			if (s_shieldTexture) {
				ImGui::Image((ImTextureID)s_shieldTexture, ImVec2(16, 16));
				ImGui::SameLine();
			}
			if (MenuItem("Run as Administrator")) {
				SecurityHelper::RunElevated(nullptr, true);
				::PostQuitMessage(0);
			}
			Separator();
		}
		if (MenuItem("Exit", nullptr, nullptr)) {
			::PostQuitMessage(0);
		}
		ImGui::EndMenu();
	}
}

void TabManager::BuildWindowMenu() {
	std::vector<std::string> names;
	for (auto& [name, win] : _windows)
		if (!win->WindowOpen)
			names.push_back(name);

	for (auto& name : names)
		_windows.erase(name);

	if (_windows.empty())
		return;

	if (BeginMenu("Window")) {
		CStringA text;
		for (auto& [name, p] : _windows) {
			if (MenuItem(name.c_str()))
				SetWindowFocus(name.c_str());
		}
		ImGui::EndMenu();
	}
}

void TabManager::BuildHelpMenu() {
	static bool open = false;
	if (BeginMenu("Help")) {
		if (MenuItem("About NtWarden..."))
			open = true;
		ImGui::EndMenu();
	}

	if (open) {
		auto title = "About NtWarden";
		if (MessageBoxResult::OK == SimpleMessageBox::ShowModal(title,
			"NtWarden (C)2023 \n\nBy Suraj Malhotra (MrT4ntr4) \n\nInspired from Pavel Yosifovich (zodiacon)"))
			open = false;
	}
}

void TabManager::AddWindow(std::shared_ptr<WindowProperties> window) {
	_windows.insert({ window->GetName(), window });
}

void TabManager::BuildMainMenu() {
	if (ImGui::BeginMainMenuBar()) {
		BuildFileMenu();
		BuildDriverMenu();
		BuildRemoteMenu();
		BuildOptionsMenu();
		BuildWindowMenu();
		BuildHelpMenu();
		ImGui::EndMainMenuBar();
	}
}

void TabManager::BuildRemoteMenu() {
	const bool connected = RemoteClient::IsConnected();

	if (BeginMenu("Remote")) {
		ImGui::Text("Server Address");
		ImGui::Separator();

		ImGui::BeginDisabled(connected || _remoteConnectPending);
		ImGui::SetNextItemWidth(160);
		ImGui::InputText("IP##remote", _remoteIP, sizeof(_remoteIP));
		ImGui::SameLine();
		ImGui::SetNextItemWidth(70);
		ImGui::InputInt("Port##remote", &_remotePort, 0, 0);
		if (_remotePort < 1) _remotePort = 1;
		if (_remotePort > 65535) _remotePort = 65535;
		ImGui::EndDisabled();

		ImGui::Separator();

		if (_remoteConnectPending) {
			const int numDots = (int)(ImGui::GetTime() * 3.0f) % 4;
			const char* dots[] = { "", ".", "..", "..." };
			ImGui::BeginDisabled(true);
			ImGui::MenuItem(std::format("Connecting{}", dots[numDots]).c_str());
			ImGui::EndDisabled();
		}
		else if (!connected) {
			if (ImGui::MenuItem("Connect")) {
				LoggerView::AddLog(LoggerView::UserModeLog, "Connecting to %s:%d...", _remoteIP, _remotePort);
				_remoteConnectPending = true;
				std::string ip = _remoteIP;
				uint16_t port = (uint16_t)_remotePort;
				_remoteConnectFuture = std::async(std::launch::async, [ip, port]() {
					auto result = RemoteClient::Connect(ip.c_str(), port);
					if (result)
						Globals::Get().SetRemoteSysInfo(RemoteClient::GetSystemInfo());
					return result;
				});
			}
		}
		else {
			if (ImGui::MenuItem("Disconnect")) {
				RemoteClient::Disconnect();
				Globals::Get().SetRemoteMode(false);
				Globals::Get().SetRemoteAddress("");
				LoggerView::AddLog(LoggerView::UserModeLog, "Disconnected from remote server");
			}
		}

		ImGui::Separator();
		if (connected)
			ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.5f, 1.0f), "Status: Connected (%s)", RemoteClient::GetConnectedAddress());
		else if (_remoteConnectPending)
			ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "Status: Connecting...");
		else
			ImGui::TextDisabled("Status: Not connected");

		ImGui::EndMenu();
	}
}
