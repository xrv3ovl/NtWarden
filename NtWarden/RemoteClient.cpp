#include "pch.h"
#include "RemoteClient.h"
#include <WS2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

SOCKET RemoteClient::_socket = INVALID_SOCKET;
std::mutex RemoteClient::_mutex;
char RemoteClient::_address[128] = {};
bool RemoteClient::_connected = false;
MODULE_INFO RemoteClient::_callbacks[200] = {};
ULONG_PTR RemoteClient::_ssdt[500] = {};
MODULE_INFO RemoteClient::_modules[200] = {};

static bool s_wsaInitialized = false;

namespace {
	std::string WideToUtf8(std::wstring_view text) {
		if (text.empty())
			return {};
		auto length = ::WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
		std::string utf8(length, '\0');
		::WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), utf8.data(), length, nullptr, nullptr);
		return utf8;
	}
}

static void EnsureWSA() {
	if (!s_wsaInitialized) {
		WSADATA wsaData;
		WSAStartup(MAKEWORD(2, 2), &wsaData);
		s_wsaInitialized = true;
	}
}

bool RemoteClient::RecvAll(void* buf, int len) {
	char* ptr = (char*)buf;
	int remaining = len;
	while (remaining > 0) {
		int n = recv(_socket, ptr, remaining, 0);
		if (n <= 0) return false;
		ptr += n;
		remaining -= n;
	}
	return true;
}

bool RemoteClient::SendAll(const void* buf, int len) {
	const char* ptr = (const char*)buf;
	int remaining = len;
	while (remaining > 0) {
		int n = send(_socket, ptr, remaining, 0);
		if (n <= 0) return false;
		ptr += n;
		remaining -= n;
	}
	return true;
}

bool RemoteClient::SendRequest(uint32_t msgType, const void* data, uint32_t dataSize) {
	WinSysMessageHeader header{};
	header.MessageType = msgType;
	header.DataSize = dataSize;
	header.Status = 0;
	if (!SendAll(&header, sizeof(header)))
		return false;
	if (dataSize > 0 && data) {
		if (!SendAll(data, dataSize))
			return false;
	}
	return true;
}

bool RemoteClient::RecvResponse(WinSysMessageHeader& header, std::vector<uint8_t>& payload) {
	if (!RecvAll(&header, sizeof(header)))
		return false;
	if (header.DataSize > 0) {
		if (header.DataSize > 64 * 1024 * 1024) // 64MB sanity limit
			return false;
		payload.resize(header.DataSize);
		if (!RecvAll(payload.data(), header.DataSize))
			return false;
	}
	else {
		payload.clear();
	}
	return true;
}

bool RemoteClient::Connect(const char* ip, uint16_t port) {
	std::lock_guard<std::mutex> lock(_mutex);
	EnsureWSA();

	if (_connected)
		Disconnect();

	_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (_socket == INVALID_SOCKET)
		return false;

	// Set connection timeout via non-blocking + select
	u_long nonBlocking = 1;
	ioctlsocket(_socket, FIONBIO, &nonBlocking);

	sockaddr_in addr{};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
		closesocket(_socket);
		_socket = INVALID_SOCKET;
		return false;
	}

	connect(_socket, (sockaddr*)&addr, sizeof(addr));

	fd_set writeSet;
	FD_ZERO(&writeSet);
	FD_SET(_socket, &writeSet);
	timeval timeout;
	timeout.tv_sec = 5;
	timeout.tv_usec = 0;

	int result = select(0, nullptr, &writeSet, nullptr, &timeout);
	if (result <= 0) {
		closesocket(_socket);
		_socket = INVALID_SOCKET;
		return false;
	}

	// Back to blocking mode
	nonBlocking = 0;
	ioctlsocket(_socket, FIONBIO, &nonBlocking);

	// Disable Nagle
	int nodelay = 1;
	setsockopt(_socket, IPPROTO_TCP, TCP_NODELAY, (const char*)&nodelay, sizeof(nodelay));

	snprintf(_address, sizeof(_address), "%s:%d", ip, port);
	_connected = true;

	// Verify with ping
	if (!PingInternal()) {
		Disconnect();
		return false;
	}

	return true;
}

void RemoteClient::Disconnect() {
	if (_socket != INVALID_SOCKET) {
		shutdown(_socket, SD_BOTH);
		closesocket(_socket);
		_socket = INVALID_SOCKET;
	}
	_connected = false;
	_address[0] = 0;
}

bool RemoteClient::IsConnected() {
	return _connected;
}

bool RemoteClient::PingInternal() {
	if (!_connected) return false;

	if (!SendRequest(MSG_REQ_PING))
		return false;

	WinSysMessageHeader header{};
	std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload))
		return false;

	return header.MessageType == MSG_RESP_PING && header.Status == WINSYS_STATUS_OK;
}

bool RemoteClient::Ping() {
	std::lock_guard<std::mutex> lock(_mutex);
	return PingInternal();
}

const char* RemoteClient::GetConnectedAddress() {
	return _address;
}

SysInfoNet RemoteClient::GetSystemInfo() {
	std::lock_guard<std::mutex> lock(_mutex);
	if (!_connected) return {};

	if (!SendRequest(MSG_REQ_SYSINFO))
		return {};

	WinSysMessageHeader header{};
	std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload) || header.MessageType != MSG_RESP_SYSINFO || header.Status != WINSYS_STATUS_OK)
		return {};

	SysInfoNet info{};
	if (!payload.empty()) {
		size_t copySize = (std::min)(payload.size(), sizeof(SysInfoNet));
		memcpy(&info, payload.data(), copySize);
	}
	return info;
}

std::vector<ProcessInfoNet> RemoteClient::GetProcesses() {
	std::lock_guard<std::mutex> lock(_mutex);
	std::vector<ProcessInfoNet> result;
	if (!_connected) return result;

	if (!SendRequest(MSG_REQ_PROCESSES)) {
		_connected = false;
		return result;
	}

	WinSysMessageHeader header{};
	std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) {
		_connected = false;
		return result;
	}

	if (header.Status != WINSYS_STATUS_OK || payload.empty())
		return result;

	size_t count = payload.size() / sizeof(ProcessInfoNet);
	ProcessInfoNet* data = (ProcessInfoNet*)payload.data();
	result.assign(data, data + count);
	return result;
}

std::vector<ServiceInfoNet> RemoteClient::GetServices() {
	std::lock_guard<std::mutex> lock(_mutex);
	std::vector<ServiceInfoNet> result;
	if (!_connected) return result;

	if (!SendRequest(MSG_REQ_SERVICES)) {
		_connected = false;
		return result;
	}

	WinSysMessageHeader header{};
	std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) {
		_connected = false;
		return result;
	}

	if (header.Status != WINSYS_STATUS_OK || payload.empty())
		return result;

	size_t count = payload.size() / sizeof(ServiceInfoNet);
	ServiceInfoNet* data = (ServiceInfoNet*)payload.data();
	result.assign(data, data + count);
	return result;
}

std::vector<ConnectionNet> RemoteClient::GetConnections() {
	std::lock_guard<std::mutex> lock(_mutex);
	std::vector<ConnectionNet> result;
	if (!_connected) return result;

	if (!SendRequest(MSG_REQ_CONNECTIONS)) {
		_connected = false;
		return result;
	}

	WinSysMessageHeader header{};
	std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) {
		_connected = false;
		return result;
	}

	if (header.Status != WINSYS_STATUS_OK || payload.empty())
		return result;

	size_t count = payload.size() / sizeof(ConnectionNet);
	ConnectionNet* data = (ConnectionNet*)payload.data();
	result.assign(data, data + count);
	return result;
}

bool RemoteClient::GetPerformanceSnapshot(PerformanceSnapshotNet& snapshot) {
	std::lock_guard<std::mutex> lock(_mutex);
	snapshot = {};
	if (!_connected)
		return false;

	if (!SendRequest(MSG_REQ_PERFORMANCE)) {
		_connected = false;
		return false;
	}

	WinSysMessageHeader header{};
	std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) {
		_connected = false;
		return false;
	}

	if (header.MessageType != MSG_RESP_PERFORMANCE || header.Status != WINSYS_STATUS_OK || payload.size() < sizeof(PerformanceSnapshotNet))
		return false;

	memcpy(&snapshot, payload.data(), sizeof(snapshot));
	return true;
}

std::vector<RegistryKeyNet> RemoteClient::EnumRegistrySubKeys(const std::wstring& path) {
	std::lock_guard<std::mutex> lock(_mutex);
	std::vector<RegistryKeyNet> result;
	if (!_connected)
		return result;

	RegistryEnumRequestNet request{};
	request.QueryType = 1;
	auto utf8 = WideToUtf8(path);
	strncpy_s(request.Path, sizeof(request.Path), utf8.c_str(), _TRUNCATE);
	if (!SendRequest(MSG_REQ_REGISTRY_ENUM, &request, sizeof(request))) {
		_connected = false;
		return result;
	}

	WinSysMessageHeader header{};
	std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) {
		_connected = false;
		return result;
	}

	if (header.MessageType != MSG_RESP_REGISTRY_ENUM || header.Status != WINSYS_STATUS_OK || payload.empty())
		return result;

	size_t count = payload.size() / sizeof(RegistryKeyNet);
	auto* data = reinterpret_cast<RegistryKeyNet*>(payload.data());
	result.assign(data, data + count);
	return result;
}

std::vector<RegistryValueNet> RemoteClient::EnumRegistryValues(const std::wstring& path) {
	std::lock_guard<std::mutex> lock(_mutex);
	std::vector<RegistryValueNet> result;
	if (!_connected)
		return result;

	RegistryEnumRequestNet request{};
	request.QueryType = 2;
	auto utf8 = WideToUtf8(path);
	strncpy_s(request.Path, sizeof(request.Path), utf8.c_str(), _TRUNCATE);
	if (!SendRequest(MSG_REQ_REGISTRY_ENUM, &request, sizeof(request))) {
		_connected = false;
		return result;
	}

	WinSysMessageHeader header{};
	std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) {
		_connected = false;
		return result;
	}

	if (header.MessageType != MSG_RESP_REGISTRY_ENUM || header.Status != WINSYS_STATUS_OK || payload.empty())
		return result;

	size_t count = payload.size() / sizeof(RegistryValueNet);
	auto* data = reinterpret_cast<RegistryValueNet*>(payload.data());
	result.assign(data, data + count);
	return result;
}

bool RemoteClient::GetKernelBase(KernelBaseInfoNet& info) {
	std::lock_guard<std::mutex> lock(_mutex);
	info = {};
	if (!_connected) return false;

	if (!SendRequest(MSG_REQ_KERNEL_BASE)) {
		_connected = false;
		return false;
	}

	WinSysMessageHeader header{};
	std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) {
		_connected = false;
		return false;
	}

	if (header.Status != WINSYS_STATUS_OK || payload.size() < sizeof(KernelBaseInfoNet))
		return false;

	memcpy(&info, payload.data(), sizeof(KernelBaseInfoNet));
	return true;
}

MODULE_INFO* RemoteClient::GetCallbacks(const CALLBACK_QUERY& query) {
	std::lock_guard<std::mutex> lock(_mutex);
	memset(_callbacks, 0, sizeof(_callbacks));
	if (!_connected) return _callbacks;

	if (!SendRequest(MSG_REQ_CALLBACKS, &query, sizeof(query))) {
		_connected = false;
		return _callbacks;
	}

	WinSysMessageHeader header{};
	std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) {
		_connected = false;
		return _callbacks;
	}

	if (header.Status == WINSYS_STATUS_OK && !payload.empty()) {
		size_t copySize = (payload.size() < sizeof(_callbacks)) ? payload.size() : sizeof(_callbacks);
		memcpy(_callbacks, payload.data(), copySize);
	}
	return _callbacks;
}

ULONG_PTR* RemoteClient::GetSSDT() {
	std::lock_guard<std::mutex> lock(_mutex);
	memset(_ssdt, 0, sizeof(_ssdt));
	if (!_connected) return _ssdt;

	if (!SendRequest(MSG_REQ_SSDT)) {
		_connected = false;
		return _ssdt;
	}

	WinSysMessageHeader header{};
	std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) {
		_connected = false;
		return _ssdt;
	}

	if (header.Status == WINSYS_STATUS_OK && !payload.empty()) {
		size_t copySize = (payload.size() < sizeof(_ssdt)) ? payload.size() : sizeof(_ssdt);
		memcpy(_ssdt, payload.data(), copySize);
	}
	return _ssdt;
}

MODULE_INFO* RemoteClient::GetModules() {
	std::lock_guard<std::mutex> lock(_mutex);
	memset(_modules, 0, sizeof(_modules));
	if (!_connected) return _modules;

	if (!SendRequest(MSG_REQ_KERNEL_MODULES)) {
		_connected = false;
		return _modules;
	}

	WinSysMessageHeader header{};
	std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) {
		_connected = false;
		return _modules;
	}

	if (header.Status == WINSYS_STATUS_OK && !payload.empty()) {
		size_t copySize = (payload.size() < sizeof(_modules)) ? payload.size() : sizeof(_modules);
		memcpy(_modules, payload.data(), copySize);
	}
	return _modules;
}

std::vector<KERNEL_PROCESS_ENTRY> RemoteClient::GetProcessObjects() {
	std::lock_guard<std::mutex> lock(_mutex);
	std::vector<KERNEL_PROCESS_ENTRY> result;
	if (!_connected) return result;

	if (!SendRequest(MSG_REQ_PROCESS_OBJECTS)) {
		_connected = false;
		return result;
	}

	WinSysMessageHeader header{};
	std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) {
		_connected = false;
		return result;
	}

	if (header.Status != WINSYS_STATUS_OK || payload.empty())
		return result;

	size_t count = payload.size() / sizeof(KERNEL_PROCESS_ENTRY);
	KERNEL_PROCESS_ENTRY* data = (KERNEL_PROCESS_ENTRY*)payload.data();
	result.assign(data, data + count);
	return result;
}

DriverHelper::CrossCheckResult RemoteClient::CrossCheckProcesses() {
	std::lock_guard<std::mutex> lock(_mutex);
	DriverHelper::CrossCheckResult result{};
	if (!_connected) return result;

	if (!SendRequest(MSG_REQ_CROSS_CHECK)) {
		_connected = false;
		return result;
	}

	WinSysMessageHeader header{};
	std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) {
		_connected = false;
		return result;
	}

	if (header.Status != WINSYS_STATUS_OK || payload.size() < sizeof(CROSS_CHECK_RESULT))
		return result;

	result.header = *(CROSS_CHECK_RESULT*)payload.data();
	if (result.header.TotalEntries > MAX_CROSS_CHECK_PROCESSES)
		result.header.TotalEntries = MAX_CROSS_CHECK_PROCESSES;

	size_t entriesOffset = sizeof(CROSS_CHECK_RESULT);
	size_t availableEntries = (payload.size() - entriesOffset) / sizeof(CROSS_CHECK_PROCESS_ENTRY);
	size_t count = (std::min)((size_t)result.header.TotalEntries, availableEntries);

	CROSS_CHECK_PROCESS_ENTRY* entries = (CROSS_CHECK_PROCESS_ENTRY*)(payload.data() + entriesOffset);
	result.entries.assign(entries, entries + count);
	return result;
}

uint16_t RemoteClient::GetDriverVersion() {
	std::lock_guard<std::mutex> lock(_mutex);
	if (!_connected) return 0;

	if (!SendRequest(MSG_REQ_DRIVER_VERSION)) {
		_connected = false;
		return 0;
	}

	WinSysMessageHeader header{};
	std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) {
		_connected = false;
		return 0;
	}

	if (header.Status == WINSYS_STATUS_OK && payload.size() >= sizeof(uint16_t))
		return *(uint16_t*)payload.data();
	return 0;
}

bool RemoteClient::SendEprocessOffsets(const EPROCESS_OFFSETS& offsets) {
	std::lock_guard<std::mutex> lock(_mutex);
	if (!_connected) return false;

	if (!SendRequest(MSG_REQ_EPROCESS_OFFSETS, &offsets, sizeof(offsets))) {
		_connected = false;
		return false;
	}

	WinSysMessageHeader header{};
	std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) {
		_connected = false;
		return false;
	}

	return header.Status == WINSYS_STATUS_OK;
}

bool RemoteClient::CreateModuleSnapshot(unsigned long& count) {
	std::lock_guard<std::mutex> lock(_mutex);
	count = 0;
	if (!_connected) return false;

	if (!SendRequest(MSG_REQ_MODULE_SNAPSHOT)) {
		_connected = false;
		return false;
	}

	WinSysMessageHeader header{};
	std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) {
		_connected = false;
		return false;
	}

	if (header.Status == WINSYS_STATUS_OK && payload.size() >= sizeof(unsigned long))
		count = *(unsigned long*)payload.data();

	return header.Status == WINSYS_STATUS_OK;
}

bool RemoteClient::QueryModulePage(unsigned long startIndex, unsigned long count, KERNEL_MODULE_ENTRY* entries, unsigned long& returnedCount) {
	std::lock_guard<std::mutex> lock(_mutex);
	returnedCount = 0;
	if (!_connected) return false;

	MODULE_PAGE_REQUEST request{ startIndex, count };
	if (!SendRequest(MSG_REQ_MODULE_PAGES, &request, sizeof(request))) {
		_connected = false;
		return false;
	}

	WinSysMessageHeader header{};
	std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) {
		_connected = false;
		return false;
	}

	if (header.Status != WINSYS_STATUS_OK || payload.empty())
		return false;

	returnedCount = (unsigned long)(payload.size() / sizeof(KERNEL_MODULE_ENTRY));
	if (returnedCount > count)
		returnedCount = count;
	memcpy(entries, payload.data(), returnedCount * sizeof(KERNEL_MODULE_ENTRY));
	return true;
}

bool RemoteClient::ReleaseModuleSnapshot() {
	std::lock_guard<std::mutex> lock(_mutex);
	if (!_connected) return false;

	if (!SendRequest(MSG_REQ_RELEASE_SNAPSHOT)) {
		_connected = false;
		return false;
	}

	WinSysMessageHeader header{};
	std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) {
		_connected = false;
		return false;
	}

	return header.Status == WINSYS_STATUS_OK;
}

// === Driver-based kernel methods ===

bool RemoteClient::GetGdt(GDT_INFO& info) {
	std::lock_guard<std::mutex> lock(_mutex);
	memset(&info, 0, sizeof(info));
	if (!_connected) return false;
	if (!SendRequest(MSG_REQ_GDT)) { _connected = false; return false; }
	WinSysMessageHeader header{}; std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) { _connected = false; return false; }
	if (header.Status != WINSYS_STATUS_OK || payload.size() < sizeof(GDT_INFO)) return false;
	memcpy(&info, payload.data(), sizeof(GDT_INFO));
	return true;
}

bool RemoteClient::GetIdt(IDT_INFO& info) {
	std::lock_guard<std::mutex> lock(_mutex);
	memset(&info, 0, sizeof(info));
	if (!_connected) return false;
	if (!SendRequest(MSG_REQ_IDT)) { _connected = false; return false; }
	WinSysMessageHeader header{}; std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) { _connected = false; return false; }
	if (header.Status != WINSYS_STATUS_OK || payload.size() < sizeof(IDT_INFO)) return false;
	memcpy(&info, payload.data(), sizeof(IDT_INFO));
	return true;
}

std::vector<WFP_FILTER_ENTRY> RemoteClient::GetWfpFilters() {
	std::lock_guard<std::mutex> lock(_mutex);
	std::vector<WFP_FILTER_ENTRY> result;
	if (!_connected) return result;
	if (!SendRequest(MSG_REQ_WFP_FILTERS)) { _connected = false; return result; }
	WinSysMessageHeader header{}; std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) { _connected = false; return result; }
	if (header.Status != WINSYS_STATUS_OK || payload.empty()) return result;
	size_t count = payload.size() / sizeof(WFP_FILTER_ENTRY);
	auto* data = (WFP_FILTER_ENTRY*)payload.data();
	result.assign(data, data + count);
	return result;
}

std::vector<WFP_CALLOUT_ENTRY> RemoteClient::GetWfpCallouts() {
	std::lock_guard<std::mutex> lock(_mutex);
	std::vector<WFP_CALLOUT_ENTRY> result;
	if (!_connected) return result;
	if (!SendRequest(MSG_REQ_WFP_CALLOUTS)) { _connected = false; return result; }
	WinSysMessageHeader header{}; std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) { _connected = false; return result; }
	if (header.Status != WINSYS_STATUS_OK || payload.empty()) return result;
	size_t count = payload.size() / sizeof(WFP_CALLOUT_ENTRY);
	auto* data = (WFP_CALLOUT_ENTRY*)payload.data();
	result.assign(data, data + count);
	return result;
}

bool RemoteClient::GetIrpDispatch(const std::string& driverName, IRP_DISPATCH_RESULT& result) {
	std::lock_guard<std::mutex> lock(_mutex);
	memset(&result, 0, sizeof(result));
	if (!_connected) return false;
	IrpDispatchRequestNet req{};
	strncpy_s(req.DriverName, sizeof(req.DriverName), driverName.c_str(), _TRUNCATE);
	if (!SendRequest(MSG_REQ_IRP_DISPATCH, &req, sizeof(req))) { _connected = false; return false; }
	WinSysMessageHeader header{}; std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) { _connected = false; return false; }
	if (header.Status != WINSYS_STATUS_OK || payload.size() < sizeof(IRP_DISPATCH_RESULT)) return false;
	memcpy(&result, payload.data(), sizeof(IRP_DISPATCH_RESULT));
	return true;
}

// === NtQuery-based methods ===

std::vector<HandleEntryNet> RemoteClient::GetHandles() {
	std::lock_guard<std::mutex> lock(_mutex);
	std::vector<HandleEntryNet> result;
	if (!_connected) return result;
	if (!SendRequest(MSG_REQ_HANDLES)) { _connected = false; return result; }
	WinSysMessageHeader header{}; std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) { _connected = false; return result; }
	if (header.Status != WINSYS_STATUS_OK || payload.empty()) return result;
	size_t count = payload.size() / sizeof(HandleEntryNet);
	auto* data = (HandleEntryNet*)payload.data();
	result.assign(data, data + count);
	return result;
}

std::vector<BigPoolEntryNet> RemoteClient::GetBigPool() {
	std::lock_guard<std::mutex> lock(_mutex);
	std::vector<BigPoolEntryNet> result;
	if (!_connected) return result;
	if (!SendRequest(MSG_REQ_BIG_POOL)) { _connected = false; return result; }
	WinSysMessageHeader header{}; std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) { _connected = false; return result; }
	if (header.Status != WINSYS_STATUS_OK || payload.empty()) return result;
	size_t count = payload.size() / sizeof(BigPoolEntryNet);
	auto* data = (BigPoolEntryNet*)payload.data();
	result.assign(data, data + count);
	return result;
}

std::vector<PoolTagEntryNet> RemoteClient::GetPoolTags() {
	std::lock_guard<std::mutex> lock(_mutex);
	std::vector<PoolTagEntryNet> result;
	if (!_connected) return result;
	if (!SendRequest(MSG_REQ_POOL_TAGS)) { _connected = false; return result; }
	WinSysMessageHeader header{}; std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) { _connected = false; return result; }
	if (header.Status != WINSYS_STATUS_OK || payload.empty()) return result;
	size_t count = payload.size() / sizeof(PoolTagEntryNet);
	auto* data = (PoolTagEntryNet*)payload.data();
	result.assign(data, data + count);
	return result;
}

std::vector<InterruptInfoNet> RemoteClient::GetInterruptInfo() {
	std::lock_guard<std::mutex> lock(_mutex);
	std::vector<InterruptInfoNet> result;
	if (!_connected) return result;
	if (!SendRequest(MSG_REQ_INTERRUPT_INFO)) { _connected = false; return result; }
	WinSysMessageHeader header{}; std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) { _connected = false; return result; }
	if (header.Status != WINSYS_STATUS_OK || payload.empty()) return result;
	size_t count = payload.size() / sizeof(InterruptInfoNet);
	auto* data = (InterruptInfoNet*)payload.data();
	result.assign(data, data + count);
	return result;
}

// === User-mode system methods ===

std::vector<EtwSessionNet> RemoteClient::GetEtwSessions() {
	std::lock_guard<std::mutex> lock(_mutex);
	std::vector<EtwSessionNet> result;
	if (!_connected) return result;
	if (!SendRequest(MSG_REQ_ETW_SESSIONS)) { _connected = false; return result; }
	WinSysMessageHeader header{}; std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) { _connected = false; return result; }
	if (header.Status != WINSYS_STATUS_OK || payload.empty()) return result;
	size_t count = payload.size() / sizeof(EtwSessionNet);
	auto* data = (EtwSessionNet*)payload.data();
	result.assign(data, data + count);
	return result;
}

std::vector<EtwProviderNet> RemoteClient::GetEtwProviders() {
	std::lock_guard<std::mutex> lock(_mutex);
	std::vector<EtwProviderNet> result;
	if (!_connected) return result;
	if (!SendRequest(MSG_REQ_ETW_PROVIDERS)) { _connected = false; return result; }
	WinSysMessageHeader header{}; std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) { _connected = false; return result; }
	if (header.Status != WINSYS_STATUS_OK || payload.empty()) return result;
	size_t count = payload.size() / sizeof(EtwProviderNet);
	auto* data = (EtwProviderNet*)payload.data();
	result.assign(data, data + count);
	return result;
}

std::vector<CertificateNet> RemoteClient::GetCertificates() {
	std::lock_guard<std::mutex> lock(_mutex);
	std::vector<CertificateNet> result;
	if (!_connected) return result;
	if (!SendRequest(MSG_REQ_CERTIFICATES)) { _connected = false; return result; }
	WinSysMessageHeader header{}; std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) { _connected = false; return result; }
	if (header.Status != WINSYS_STATUS_OK || payload.empty()) return result;
	size_t count = payload.size() / sizeof(CertificateNet);
	auto* data = (CertificateNet*)payload.data();
	result.assign(data, data + count);
	return result;
}

std::vector<AdapterInfoNet> RemoteClient::GetAdapters() {
	std::lock_guard<std::mutex> lock(_mutex);
	std::vector<AdapterInfoNet> result;
	if (!_connected) return result;
	if (!SendRequest(MSG_REQ_ADAPTERS)) { _connected = false; return result; }
	WinSysMessageHeader header{}; std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) { _connected = false; return result; }
	if (header.Status != WINSYS_STATUS_OK || payload.empty()) return result;
	size_t count = payload.size() / sizeof(AdapterInfoNet);
	auto* data = (AdapterInfoNet*)payload.data();
	result.assign(data, data + count);
	return result;
}

std::vector<RpcEndpointNet> RemoteClient::GetRpcEndpoints() {
	std::lock_guard<std::mutex> lock(_mutex);
	std::vector<RpcEndpointNet> result;
	if (!_connected) return result;
	if (!SendRequest(MSG_REQ_RPC_ENDPOINTS)) { _connected = false; return result; }
	WinSysMessageHeader header{}; std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) { _connected = false; return result; }
	if (header.Status != WINSYS_STATUS_OK || payload.empty()) return result;
	size_t count = payload.size() / sizeof(RpcEndpointNet);
	auto* data = (RpcEndpointNet*)payload.data();
	result.assign(data, data + count);
	return result;
}

std::vector<NamedPipeNet> RemoteClient::GetNamedPipes() {
	std::lock_guard<std::mutex> lock(_mutex);
	std::vector<NamedPipeNet> result;
	if (!_connected) return result;
	if (!SendRequest(MSG_REQ_NAMED_PIPES)) { _connected = false; return result; }
	WinSysMessageHeader header{}; std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) { _connected = false; return result; }
	if (header.Status != WINSYS_STATUS_OK || payload.empty()) return result;
	size_t count = payload.size() / sizeof(NamedPipeNet);
	auto* data = (NamedPipeNet*)payload.data();
	result.assign(data, data + count);
	return result;
}

std::vector<MiniFilterNet> RemoteClient::GetMiniFilters() {
	std::lock_guard<std::mutex> lock(_mutex);
	std::vector<MiniFilterNet> result;
	if (!_connected) return result;
	if (!SendRequest(MSG_REQ_MINIFILTERS)) { _connected = false; return result; }
	WinSysMessageHeader header{}; std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) { _connected = false; return result; }
	if (header.Status != WINSYS_STATUS_OK || payload.empty()) return result;
	size_t count = payload.size() / sizeof(MiniFilterNet);
	auto* data = (MiniFilterNet*)payload.data();
	result.assign(data, data + count);
	return result;
}

std::vector<FilterInstanceNet> RemoteClient::GetFilterInstances(const std::string& filterName) {
	std::lock_guard<std::mutex> lock(_mutex);
	std::vector<FilterInstanceNet> result;
	if (!_connected) return result;
	FilterInstanceRequestNet req{};
	strncpy_s(req.FilterName, sizeof(req.FilterName), filterName.c_str(), _TRUNCATE);
	if (!SendRequest(MSG_REQ_FILTER_INSTANCES, &req, sizeof(req))) { _connected = false; return result; }
	WinSysMessageHeader header{}; std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) { _connected = false; return result; }
	if (header.Status != WINSYS_STATUS_OK || payload.empty()) return result;
	size_t count = payload.size() / sizeof(FilterInstanceNet);
	auto* data = (FilterInstanceNet*)payload.data();
	result.assign(data, data + count);
	return result;
}

std::vector<ObjectEntryNet> RemoteClient::GetObjDirectory(const std::string& path) {
	std::lock_guard<std::mutex> lock(_mutex);
	std::vector<ObjectEntryNet> result;
	if (!_connected) return result;
	ObjDirectoryRequestNet req{};
	strncpy_s(req.Path, sizeof(req.Path), path.c_str(), _TRUNCATE);
	if (!SendRequest(MSG_REQ_OBJ_DIRECTORY, &req, sizeof(req))) { _connected = false; return result; }
	WinSysMessageHeader header{}; std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) { _connected = false; return result; }
	if (header.Status != WINSYS_STATUS_OK || payload.empty()) return result;
	size_t count = payload.size() / sizeof(ObjectEntryNet);
	auto* data = (ObjectEntryNet*)payload.data();
	result.assign(data, data + count);
	return result;
}

std::vector<NtdllFunctionNet> RemoteClient::GetNtdllFunctions() {
	std::lock_guard<std::mutex> lock(_mutex);
	std::vector<NtdllFunctionNet> result;
	if (!_connected) return result;
	if (!SendRequest(MSG_REQ_NTDLL_FUNCTIONS)) { _connected = false; return result; }
	WinSysMessageHeader header{}; std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) { _connected = false; return result; }
	if (header.Status != WINSYS_STATUS_OK || payload.empty()) return result;
	size_t count = payload.size() / sizeof(NtdllFunctionNet);
	auto* data = (NtdllFunctionNet*)payload.data();
	result.assign(data, data + count);
	return result;
}

std::vector<InstrumentationCbNet> RemoteClient::GetInstrumentationCallbacks() {
	std::lock_guard<std::mutex> lock(_mutex);
	std::vector<InstrumentationCbNet> result;
	if (!_connected) return result;
	if (!SendRequest(MSG_REQ_INSTRUMENTATION_CB)) { _connected = false; return result; }
	WinSysMessageHeader header{}; std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) { _connected = false; return result; }
	if (header.Status != WINSYS_STATUS_OK || payload.empty()) return result;
	size_t count = payload.size() / sizeof(InstrumentationCbNet);
	auto* data = (InstrumentationCbNet*)payload.data();
	result.assign(data, data + count);
	return result;
}

bool RemoteClient::GetDseStatus(DseStatusNet& info) {
	std::lock_guard<std::mutex> lock(_mutex);
	memset(&info, 0, sizeof(info));
	if (!_connected) return false;
	if (!SendRequest(MSG_REQ_DSE_STATUS)) { _connected = false; return false; }
	WinSysMessageHeader header{}; std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) { _connected = false; return false; }
	if (header.Status != WINSYS_STATUS_OK || payload.size() < sizeof(DseStatusNet)) return false;
	memcpy(&info, payload.data(), sizeof(DseStatusNet));
	return true;
}

std::vector<KernelIntegrityNet> RemoteClient::GetKernelIntegrity() {
	std::lock_guard<std::mutex> lock(_mutex);
	std::vector<KernelIntegrityNet> result;
	if (!_connected) return result;
	if (!SendRequest(MSG_REQ_KERNEL_INTEGRITY)) { _connected = false; return result; }
	WinSysMessageHeader header{}; std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) { _connected = false; return result; }
	if (header.Status != WINSYS_STATUS_OK || payload.empty()) return result;
	size_t count = payload.size() / sizeof(KernelIntegrityNet);
	auto* data = (KernelIntegrityNet*)payload.data();
	result.assign(data, data + count);
	return result;
}

std::vector<ByovdEntryNet> RemoteClient::GetByovdScan() {
	std::lock_guard<std::mutex> lock(_mutex);
	std::vector<ByovdEntryNet> result;
	if (!_connected) return result;
	if (!SendRequest(MSG_REQ_BYOVD_SCAN)) { _connected = false; return result; }
	WinSysMessageHeader header{}; std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) { _connected = false; return result; }
	if (header.Status != WINSYS_STATUS_OK || payload.empty()) return result;
	size_t count = payload.size() / sizeof(ByovdEntryNet);
	auto* data = (ByovdEntryNet*)payload.data();
	result.assign(data, data + count);
	return result;
}

bool RemoteClient::MemoryRead(const MEMORY_READ_REQUEST& request, MEMORY_READ_RESULT& result) {
	std::lock_guard<std::mutex> lock(_mutex);
	memset(&result, 0, sizeof(result));
	if (!_connected) return false;
	MemoryReadRequestNet req{};
	req.Pid = request.Pid;
	req.Address = request.Address;
	req.Size = request.Size;
	if (!SendRequest(MSG_REQ_MEMORY_READ, &req, sizeof(req))) { _connected = false; return false; }
	WinSysMessageHeader header{}; std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) { _connected = false; return false; }
	if (header.Status != WINSYS_STATUS_OK || payload.size() < sizeof(MemoryReadResponseNet)) return false;
	auto* resp = (const MemoryReadResponseNet*)payload.data();
	result.BytesRead = resp->BytesRead;
	if (result.BytesRead > sizeof(result.Data)) result.BytesRead = sizeof(result.Data);
	memcpy(result.Data, resp->Data, result.BytesRead);
	return true;
}

bool RemoteClient::MemoryWrite(const MEMORY_WRITE_REQUEST& request, MEMORY_WRITE_RESULT& result) {
	std::lock_guard<std::mutex> lock(_mutex);
	memset(&result, 0, sizeof(result));
	if (!_connected) return false;
	MemoryWriteRequestNet req{};
	req.Pid = request.Pid;
	req.Address = request.Address;
	req.Size = request.Size;
	if (request.Size <= sizeof(req.Data))
		memcpy(req.Data, request.Data, request.Size);
	if (!SendRequest(MSG_REQ_MEMORY_WRITE, &req, sizeof(req))) { _connected = false; return false; }
	WinSysMessageHeader header{}; std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) { _connected = false; return false; }
	if (header.Status != WINSYS_STATUS_OK || payload.size() < sizeof(MemoryWriteResponseNet)) return false;
	auto* resp = (const MemoryWriteResponseNet*)payload.data();
	result.BytesWritten = resp->BytesWritten;
	return true;
}

bool RemoteClient::GetCiPolicy(uint32_t& ciOptions) {
	std::lock_guard<std::mutex> lock(_mutex);
	ciOptions = 0;
	if (!_connected) return false;
	if (!SendRequest(MSG_REQ_CI_POLICY)) { _connected = false; return false; }
	WinSysMessageHeader header{}; std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) { _connected = false; return false; }
	if (header.Status != WINSYS_STATUS_OK || payload.size() < sizeof(CiPolicyNet)) return false;
	auto* net = (const CiPolicyNet*)payload.data();
	ciOptions = net->CiOptions;
	return true;
}

std::vector<HypervisorHookEntryNet> RemoteClient::GetHypervisorHooks() {
	std::lock_guard<std::mutex> lock(_mutex);
	std::vector<HypervisorHookEntryNet> result;
	if (!_connected) return result;
	if (!SendRequest(MSG_REQ_HYPERVISOR_HOOKS)) { _connected = false; return result; }
	WinSysMessageHeader header{}; std::vector<uint8_t> payload;
	if (!RecvResponse(header, payload)) { _connected = false; return result; }
	if (header.Status != WINSYS_STATUS_OK || payload.empty()) return result;
	size_t count = payload.size() / sizeof(HypervisorHookEntryNet);
	auto* data = (HypervisorHookEntryNet*)payload.data();
	result.assign(data, data + count);
	return result;
}
