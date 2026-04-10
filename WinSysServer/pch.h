#pragma once

// Prevent STATUS_* macros from being defined in winnt.h
// (phnt_windows.h will handle this properly via ntstatus.h)
#ifndef WIN32_NO_STATUS
#define WIN32_NO_STATUS
#endif

// WinSock2 MUST come before Windows.h to avoid winsock.h conflicts
#include <WinSock2.h>
#include <WS2tcpip.h>

// Standard library headers needed by WinSys headers
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <functional>
#include <algorithm>

// phnt headers (includes Windows.h with WIN32_LEAN_AND_MEAN)
// phnt_windows.h handles WIN32_NO_STATUS/ntstatus.h internally
#define PHNT_MODE PHNT_MODE_USER
#define PHNT_VERSION PHNT_THRESHOLD
#include <phnt_windows.h>
#include <phnt.h>

#undef NTDDI_VERSION
#define NTDDI_VERSION NTDDI_WIN7

#include <iphlpapi.h>
#include <tcpmib.h>

// WIL
#include <wil/resource.h>

#include <SetupAPI.h>
