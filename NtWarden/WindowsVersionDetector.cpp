#include "pch.h"
#include "WindowsVersionDetector.h"

#include <winternl.h>

namespace {
	using RtlGetVersionPtr = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);
}

WindowsBuildInfo WindowsVersionDetector::Detect() {
	WindowsBuildInfo info;

	if (auto ntdll = ::GetModuleHandleW(L"ntdll.dll")) {
		auto rtlGetVersion = reinterpret_cast<RtlGetVersionPtr>(::GetProcAddress(ntdll, "RtlGetVersion"));
		if (rtlGetVersion) {
			RTL_OSVERSIONINFOEXW versionInfo{};
			versionInfo.dwOSVersionInfoSize = sizeof(versionInfo);
			if (rtlGetVersion(reinterpret_cast<PRTL_OSVERSIONINFOW>(&versionInfo)) == 0) {
				info.Major = versionInfo.dwMajorVersion;
				info.Minor = versionInfo.dwMinorVersion;
				info.Build = versionInfo.dwBuildNumber;
			}
		}
	}

	DWORD ubr = 0;
	DWORD ubrSize = sizeof(ubr);
	::RegGetValueW(HKEY_LOCAL_MACHINE,
		L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
		L"UBR",
		RRF_RT_REG_DWORD,
		nullptr,
		&ubr,
		&ubrSize);
	info.Ubr = ubr;

	wchar_t displayVersion[64]{};
	DWORD displayVersionSize = sizeof(displayVersion);
	if (::RegGetValueW(HKEY_LOCAL_MACHINE,
		L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
		L"DisplayVersion",
		RRF_RT_REG_SZ,
		nullptr,
		displayVersion,
		&displayVersionSize) == ERROR_SUCCESS) {
		info.DisplayVersion = displayVersion;
	}

	wchar_t systemDirectory[MAX_PATH]{};
	if (::GetSystemDirectoryW(systemDirectory, _countof(systemDirectory))) {
		info.KernelImage = std::wstring(systemDirectory) + L"\\ntoskrnl.exe";
	}

	return info;
}
