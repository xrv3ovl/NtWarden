#pragma once

#include "ProcessInfo.h"
#include "../WinSys/ProcessVMTracker.h"
#include "WindowProperties.h"
#include <vector>
#include <string>
#include <future>

class ProcessProperties : public WindowProperties {
public:
	struct DllEntry {
		std::string ModuleName;
		std::string ModulePath;
		unsigned long long BaseAddress{ 0 };
		unsigned long Size{ 0 };
		bool ExistsOnDisk{ false };
		bool SideLoadCandidate{ false };
	};

	struct HandleEntry {
		unsigned long long HandleValue{ 0 };
		unsigned long long Object{ 0 };
		unsigned long GrantedAccess{ 0 };
		unsigned long Attributes{ 0 };
		std::string TypeName;
		std::string ObjectName;
		std::string DecodedAccess;
		std::string SecurityNote;
		bool Suspicious{ false };
	};

	ProcessProperties(std::string name, std::shared_ptr<WinSys::ProcessInfo> pi);
	WinSys::ProcessInfo* GetProcess() const;
	void SetProcess(std::shared_ptr<WinSys::ProcessInfo> pi);
	void RefreshMemoryRegions();
	void ForceRefreshMemoryRegions();
	const std::vector<std::shared_ptr<WinSys::MemoryRegionItem>>& GetMemoryRegions() const;
	void RefreshModules();
	void ForceRefreshModules();
	const std::vector<DllEntry>& GetModules() const;
	void RefreshHandles();
	void ForceRefreshHandles();
	const std::vector<HandleEntry>& GetHandles() const;
	bool IsHandleRefreshPending() const;

private:
	static std::vector<HandleEntry> EnumHandlesAsync(uint32_t pid);
	static void ClassifyHandleSecurity(HandleEntry& he);

	std::shared_ptr<WinSys::ProcessInfo> _pi;
	std::unique_ptr<WinSys::ProcessVMTracker> _vmTracker;
	std::vector<std::shared_ptr<WinSys::MemoryRegionItem>> _emptyRegions;
	std::vector<DllEntry> _modules;
	std::vector<HandleEntry> _handles;
	std::future<std::vector<HandleEntry>> _handleFuture;
	bool _handleRefreshPending{ false };
	ULONGLONG _lastRegionRefreshTick{ 0 };
	ULONGLONG _lastModuleRefreshTick{ 0 };
	ULONGLONG _lastHandleRefreshTick{ 0 };
};

