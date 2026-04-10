// pch.h: This is a precompiled header file.
// Files listed below are compiled only once, improving build performance for future builds.
// This also affects IntelliSense performance, including code completion and many code browsing features.
// However, files listed here are ALL re-compiled if any one of them is updated between builds.
// Do not add files here that you will be updating frequently as this negates the performance advantage.

#pragma once

#define PHNT_MODE PHNT_MODE_USER
#define PHNT_VERSION PHNT_THRESHOLD	// Windows 10

#include <phnt_windows.h>
#include <phnt.h>

#undef NTDDI_VERSION
#define NTDDI_VERSION NTDDI_WIN7


#include <WinSock2.h>
#include <WS2tcpip.h>
#include <iphlpapi.h>
#include <tcpmib.h>
#include <tdh.h>



#include <wil\resource.h>
#include <SetupAPI.h>

#include <vector>
#include <memory>
#include <string>
#include <unordered_map>
#include <functional>

#pragma comment(lib,"ntdll")

