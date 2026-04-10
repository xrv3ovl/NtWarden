#pragma once

// WinSock2 MUST come before Windows.h to avoid winsock.h conflicts
// Step 1: Define WIN32_NO_STATUS so Windows.h doesn't define STATUS_* macros
#ifndef WIN32_NO_STATUS
#define WIN32_NO_STATUS
#endif
#include <WinSock2.h>
#include <WS2tcpip.h>

#include <Windows.h>

// Step 2: Undef WIN32_NO_STATUS and include ntstatus.h to get STATUS_* constants
// (needed by ATL and WIL)
#ifdef WIN32_NO_STATUS
#undef WIN32_NO_STATUS
#endif
#include <ntstatus.h>

#include <atlbase.h>
#include <atlstr.h>
#include <atltime.h>
#include <string>
#include <vector>
#include <memory>
#include <strsafe.h>
#include <unordered_map>
#include <wil\resource.h>
