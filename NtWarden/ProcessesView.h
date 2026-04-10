#pragma once

#include "WinSys.h"
#include "ProcessInfoEx.h"
#include "MessageBox.h"
#include "ProcessProperties.h"
#include "ProcessSecurityView.h"
#include "ViewBase.h"
#include "WindowProperties.h"
#include <d3d11_1.h>
#include <future>
#include "WinSysProtocol.h"

struct ImGuiTableSortSpecsColumn;
class TabManager;

class ProcessesView : public ViewBase {
public:
	ProcessesView();
	void BuildWindow();
	void RefreshNow();

private:
	struct ProcessSecurityWindow : WindowProperties {
		ProcessSecurityWindow(std::string name, std::shared_ptr<WinSys::ProcessInfo> pi)
			: WindowProperties(std::move(name)), Process(std::move(pi)) {
		}

		std::shared_ptr<WinSys::ProcessInfo> Process;
		ProcessSecurityView View;
	};

	void DoSort(int col, bool asc);
	ProcessInfoEx& GetProcessInfoEx(WinSys::ProcessInfo* pi) const;
	void DoUpdate();
	bool KillProcess(uint32_t id);
	bool TryKillProcess(WinSys::ProcessInfo* pi, bool& success);

	void BuildTable();
	void BuildViewMenu();
	void BuildProcessMenu();
	void BuildToolBar();

	void BuildPriorityClassMenu(WinSys::ProcessInfo* pi);
	bool GotoFileLocation(WinSys::ProcessInfo* pi);
	void TogglePause();
	void BuildPropertiesWindow(ProcessProperties* props);
	void BuildSecurityWindow(ProcessSecurityWindow* window);
	
	std::shared_ptr<ProcessProperties> GetProcessProperties(WinSys::ProcessInfo* pi);
	std::shared_ptr<ProcessProperties> GetOrAddProcessProperties(const std::shared_ptr<WinSys::ProcessInfo>& pi);
	std::shared_ptr<ProcessSecurityWindow> GetProcessSecurityWindow(WinSys::ProcessInfo* pi);
	std::shared_ptr<ProcessSecurityWindow> GetOrAddProcessSecurityWindow(const std::shared_ptr<WinSys::ProcessInfo>& pi);

	static CStringA ProcessAttributesToString(ProcessAttributes attributes);

	CComPtr<ID3D11ShaderResourceView> m_spImage;
	WinSys::ProcessManager _pm;
	std::vector<std::shared_ptr<WinSys::ProcessInfo>> _processes;
	mutable std::unordered_map<WinSys::ProcessOrThreadKey, ProcessInfoEx> _processesEx;
	std::unordered_map<WinSys::ProcessOrThreadKey, std::shared_ptr<ProcessProperties>> _processProperties;
	std::unordered_map<WinSys::ProcessOrThreadKey, std::shared_ptr<ProcessSecurityWindow>> _processSecurityWindows;
	const ImGuiTableColumnSortSpecs* _specs = nullptr;
	std::shared_ptr <WinSys::ProcessInfo> _selectedProcess;
	bool _modalOpen : 1 = false, _killFailed : 1 = false;

	// Async remote fetch
	std::future<std::vector<ProcessInfoNet>> _remoteFuture;
	bool _remoteFetchPending = false;
};
