#pragma once

#include "ProcessesView.h"
#include "ServicesView.h"
#include "ModulesView.h"
#include "ETWView.h"
#include "NetworkView.h"

#include "RootCertificatesView.h"
#include "RegistryView.h"
#include "NdisView.h"
#include "SymbolView.h"
#include "MiniFilterView.h"
#include "ProcessObjectsView.h"
#include "KernelMemoryView.h"
#include "ObjectManagerView.h"
#include "KernelTimersView.h"
#include "KernelHooksView.h"
#include "UserHooksView.h"
#include "IPCView.h"
#include "GdtIdtView.h"
#include "IrpDispatchView.h"
#include "WfpView.h"

#include "ProcessSecurityView.h"
#include "DseStatusView.h"
#include "CiPolicyView.h"
#include "KernelIntegrityView.h"
#include "HypervisorHookView.h"
#include "MemoryView.h"

#include "WindowsVersionDetector.h"
#include <future>

enum class Theme {
	Classic,
	Light,
	Dark,
	RedSamurai,
	NeonBlueGreen
};

class TabManager {
public:
	TabManager();

	void BuildMainMenu();
	void BuildTabs();
	void BuildOptionsMenu();
	void BuildDriverMenu();
	void BuildRemoteMenu();
	void BuildFileMenu();
	void BuildWindowMenu();
	void BuildHelpMenu();
	void BuildMainModeWindow();
	void BuildUserModeContent();
	void BuildKernelModeContent();
	void BuildPerformanceOverlay();
	bool IsPerformanceOverlayEnabled() const;
	Theme GetTheme() const { return _theme; }

	void AddWindow(std::shared_ptr<WindowProperties> window);

private:
	void LogDriverFailure(const char* prefix);
	void PumpKernelLogs();
	void RefreshCurrentTab();
	std::unordered_map<std::string, std::shared_ptr<WindowProperties>> _windows;
	std::unique_ptr<ProcessesView> _procView;
	std::unique_ptr<ServicesView> _svcView;
	std::unique_ptr<ModulesView> _modView;
	std::unique_ptr<ETWView> _etwView;
	std::unique_ptr<NetworkView> _netView;

	std::unique_ptr<RootCertificatesView> _rootCertView;
	std::unique_ptr<RegistryView> _registryView;
	std::unique_ptr<NdisView> _ndisView;
	std::unique_ptr<SymbolView> _symbolView;
	std::unique_ptr<MiniFilterView> _miniFilterView;
	std::unique_ptr<ProcessObjectsView> _processObjectsView;
	std::unique_ptr<KernelMemoryView> _kernelMemoryView;
	std::unique_ptr<ObjectManagerView> _objectManagerView;
	std::unique_ptr<KernelTimersView> _kernelTimersView;
	std::unique_ptr<KernelHooksView> _kernelHooksView;
	std::unique_ptr<IPCView> _ipcView;
	std::unique_ptr<GdtIdtView> _gdtIdtView;
	std::unique_ptr<IrpDispatchView> _irpDispatchView;
	std::unique_ptr<WfpView> _wfpView;

	std::unique_ptr<ProcessSecurityView> _processSecurityView;
	std::unique_ptr<DseStatusView> _dseStatusView;
	std::unique_ptr<CiPolicyView> _ciPolicyView;
	std::unique_ptr<KernelIntegrityView> _kernelIntegrityView;
	std::unique_ptr<HypervisorHookView> _hypervisorHookView;
	std::unique_ptr<MemoryView> _memoryView;

	WindowsBuildInfo _buildInfo;
	Theme _theme = Theme::NeonBlueGreen;
	bool _alwaysOnTop;
	bool _performanceOverlayEnabled{ false };
	float _performanceOverlayAlpha{ 0.38f };
	bool _performanceOverlayCompact{ true };
	bool _showingKernelMode{ false };
	std::string _activeUserTab{ "Processes" };
	std::string _activeUserNetworkTab{ "Connections" };
	std::string _activeKernelTab{ "Process Objects" };
	char _remoteIP[64]{ "192.168.1.100" };
	int _remotePort{ 50002 };

	// Async remote connect
	std::future<bool> _remoteConnectFuture;
	bool _remoteConnectPending{ false };
	unsigned long _nextKernelLogSequence{ 0 };
	unsigned long _lastKernelLogSequenceSeen{ 0 };
	std::chrono::steady_clock::time_point _lastKernelLogPoll{};
};

