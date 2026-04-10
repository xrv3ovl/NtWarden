#pragma once

#include "WinSysProtocol.h"
#include "DriverHelper.h"
#include "../KWinSys/KWinSysPublic.h"
#include <vector>
#include <string>
#include <mutex>

struct RemoteClient abstract final {
	static bool Connect(const char* ip, uint16_t port = WINSYS_DEFAULT_PORT);
	static void Disconnect();
	static bool IsConnected();
	static bool Ping();
	static const char* GetConnectedAddress();
	static SysInfoNet GetSystemInfo();

	// User-mode data
	static std::vector<ProcessInfoNet> GetProcesses();
	static std::vector<ServiceInfoNet> GetServices();
	static std::vector<ConnectionNet> GetConnections();
	static bool GetPerformanceSnapshot(PerformanceSnapshotNet& snapshot);
	static std::vector<RegistryKeyNet> EnumRegistrySubKeys(const std::wstring& path);
	static std::vector<RegistryValueNet> EnumRegistryValues(const std::wstring& path);
	static std::vector<EtwSessionNet> GetEtwSessions();
	static std::vector<EtwProviderNet> GetEtwProviders();
	static std::vector<CertificateNet> GetCertificates();
	static std::vector<AdapterInfoNet> GetAdapters();
	static std::vector<RpcEndpointNet> GetRpcEndpoints();
	static std::vector<NamedPipeNet> GetNamedPipes();
	static std::vector<MiniFilterNet> GetMiniFilters();
	static std::vector<FilterInstanceNet> GetFilterInstances(const std::string& filterName);
	static std::vector<ObjectEntryNet> GetObjDirectory(const std::string& path);
	static std::vector<NtdllFunctionNet> GetNtdllFunctions();
	static std::vector<HandleEntryNet> GetHandles();
	static std::vector<BigPoolEntryNet> GetBigPool();
	static std::vector<PoolTagEntryNet> GetPoolTags();
	static std::vector<InterruptInfoNet> GetInterruptInfo();

	// Security inspection
	static std::vector<InstrumentationCbNet> GetInstrumentationCallbacks();
	static bool GetDseStatus(DseStatusNet& info);
	static std::vector<KernelIntegrityNet> GetKernelIntegrity();
	static std::vector<ByovdEntryNet> GetByovdScan();
	static bool MemoryRead(const MEMORY_READ_REQUEST& request, MEMORY_READ_RESULT& result);
	static bool MemoryWrite(const MEMORY_WRITE_REQUEST& request, MEMORY_WRITE_RESULT& result);
	static bool GetCiPolicy(uint32_t& ciOptions);
	static std::vector<HypervisorHookEntryNet> GetHypervisorHooks();

	// Kernel-mode data
	static bool GetKernelBase(KernelBaseInfoNet& info);
	static bool GetGdt(GDT_INFO& info);
	static bool GetIdt(IDT_INFO& info);
	static std::vector<WFP_FILTER_ENTRY> GetWfpFilters();
	static std::vector<WFP_CALLOUT_ENTRY> GetWfpCallouts();
	static bool GetIrpDispatch(const std::string& driverName, IRP_DISPATCH_RESULT& result);
	static MODULE_INFO* GetCallbacks(const CALLBACK_QUERY& query);
	static ULONG_PTR* GetSSDT();
	static MODULE_INFO* GetModules();
	static std::vector<KERNEL_PROCESS_ENTRY> GetProcessObjects();
	static DriverHelper::CrossCheckResult CrossCheckProcesses();
	static uint16_t GetDriverVersion();
	static bool SendEprocessOffsets(const EPROCESS_OFFSETS& offsets);
	static bool CreateModuleSnapshot(unsigned long& count);
	static bool QueryModulePage(unsigned long startIndex, unsigned long count, KERNEL_MODULE_ENTRY* entries, unsigned long& returnedCount);
	static bool ReleaseModuleSnapshot();

private:
	static bool SendRequest(uint32_t msgType, const void* data = nullptr, uint32_t dataSize = 0);
	static bool RecvResponse(WinSysMessageHeader& header, std::vector<uint8_t>& payload);
	static bool RecvAll(void* buf, int len);
	static bool SendAll(const void* buf, int len);
	static bool PingInternal(); // lock-free version for internal use

	static SOCKET _socket;
	static std::mutex _mutex;
	static char _address[128];
	static bool _connected;

	// Static buffers for kernel data (mirrors DriverHelper pattern)
	static MODULE_INFO _callbacks[200];
	static ULONG_PTR _ssdt[500];
	static MODULE_INFO _modules[200];
};
