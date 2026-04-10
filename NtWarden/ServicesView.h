#pragma once

#include "WinSys.h"
#include "MessageBox.h"
#include "ServiceInfo.h"
#include "ServiceManager.h"
#include "Service.h"
#include "ViewBase.h"
#include <d3d11_1.h>
#include <future>
#include <unordered_map>
#include "WinSysProtocol.h"


struct ImGuiTableSortSpecsColumn;
class TabManager;

class ServicesView : public ViewBase {
public:
	ServicesView();
	void BuildWindow();
	void RefreshNow();

private:
	void DoSort(int col, bool asc);
	void DoUpdate();
	bool KillService(uint32_t id);
	bool TryKillService(WinSys::ServiceInfo* pi, bool& success);

	void BuildTable();
	void BuildViewMenu();
	void BuildServiceMenu();
	void BuildToolBar();

	void BuildPriorityClassMenu(WinSys::ServiceInfo* pi);
	bool GotoFileLocation(WinSys::ServiceInfo* pi);
	PCWSTR ServiceStateToString(WinSys::ServiceState state);
	const std::wstring& GetBinaryPath(const std::wstring& serviceName);

private:
	CComPtr<ID3D11ShaderResourceView> m_spImage;
	WinSys::ServiceManager _sm;
	//std::vector<WinSys::ServiceInfo> _services;
	std::vector<std::shared_ptr<WinSys::ServiceInfo>> _services;
	const ImGuiTableColumnSortSpecs* _specs = nullptr;
	std::shared_ptr<WinSys::ServiceInfo> _selectedService;
	bool _modalOpen : 1 = false, _killFailed : 1 = false;

	// Binary path cache (local mode)
	std::unordered_map<std::wstring, std::wstring> _binaryPaths;

	// Binary path cache (remote mode)
	std::unordered_map<std::wstring, std::wstring> _remoteBinaryPaths;

	// Async remote fetch
	std::future<std::vector<ServiceInfoNet>> _remoteFuture;
	bool _remoteFetchPending = false;
};
