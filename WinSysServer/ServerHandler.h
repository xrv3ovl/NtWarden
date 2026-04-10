#pragma once

#include "..\NtWarden\WinSysProtocol.h"
#include "..\KWinSys\KWinSysPublic.h"
#include "..\WinSys\ProcessManager.h"
#include "..\WinSys\ProcessInfo.h"
#include "..\WinSys\ServiceManager.h"
#include "..\WinSys\ActiveConnectionTracker.h"
#include "DriverHelper.h"

class ServerHandler {
public:
	ServerHandler();
	void HandleClient(SOCKET clientSocket);

private:
	bool SendResponse(SOCKET sock, uint32_t msgType, uint32_t status, const void* data, uint32_t dataSize);
	bool RecvAll(SOCKET sock, void* buf, int len);
	bool SendAll(SOCKET sock, const void* buf, int len);

	void HandlePing(SOCKET sock);
	void HandleProcesses(SOCKET sock);
	void HandleServices(SOCKET sock);
	void HandleConnections(SOCKET sock);
	void HandleCallbacks(SOCKET sock, const void* payload, uint32_t size);
	void HandleSSDT(SOCKET sock);
	void HandleKernelModules(SOCKET sock);
	void HandleProcessObjects(SOCKET sock);
	void HandleDriverVersion(SOCKET sock);
	void HandleModuleSnapshot(SOCKET sock);
	void HandleModulePages(SOCKET sock, const void* payload, uint32_t size);
	void HandleReleaseSnapshot(SOCKET sock);
	void HandleEprocessOffsets(SOCKET sock, const void* payload, uint32_t size);
	void HandleSysInfo(SOCKET sock);
	void HandleCrossCheck(SOCKET sock);
	void HandleKernelBase(SOCKET sock);
	void HandleGdt(SOCKET sock);
	void HandleIdt(SOCKET sock);
	void HandleWfpFilters(SOCKET sock);
	void HandleWfpCallouts(SOCKET sock);
	void HandleIrpDispatch(SOCKET sock, const void* payload, uint32_t size);
	void HandleHandles(SOCKET sock);
	void HandleBigPool(SOCKET sock);
	void HandlePoolTags(SOCKET sock);
	void HandleInterruptInfo(SOCKET sock);
	void HandleEtwSessions(SOCKET sock);
	void HandleEtwProviders(SOCKET sock);
	void HandleCertificates(SOCKET sock);
	void HandleAdapters(SOCKET sock);
	void HandleRpcEndpoints(SOCKET sock);
	void HandleNamedPipes(SOCKET sock);
	void HandleMiniFilters(SOCKET sock);
	void HandleFilterInstances(SOCKET sock, const void* payload, uint32_t size);
	void HandleObjDirectory(SOCKET sock, const void* payload, uint32_t size);
	void HandleNtdllFunctions(SOCKET sock);
	void HandlePerformance(SOCKET sock);
	void HandleRegistryEnum(SOCKET sock, const void* payload, uint32_t size);
	void HandleInstrumentationCallbacks(SOCKET sock);
	void HandleDseStatus(SOCKET sock);
	void HandleKernelIntegrity(SOCKET sock);
	void HandleByovdScan(SOCKET sock);
	void HandleMemoryRead(SOCKET sock, const void* payload, uint32_t size);
	void HandleMemoryWrite(SOCKET sock, const void* payload, uint32_t size);
	void HandleCiPolicy(SOCKET sock);
	void HandleHypervisorHooks(SOCKET sock);

	WinSys::ProcessManager _pm;
	WinSys::ActiveConnectionTracker _tracker;
};
