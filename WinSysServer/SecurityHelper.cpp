#include "pch.h"
#include "SecurityHelper.h"

bool SecurityHelper::IsRunningElevated() {
	static bool runningElevated = false;
	static bool runningElevatedCheck = false;
	if (runningElevatedCheck)
		return runningElevated;

	runningElevatedCheck = true;
	wil::unique_handle hToken;
	if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, hToken.addressof()))
		return false;

	TOKEN_ELEVATION te;
	DWORD len;
	if (::GetTokenInformation(hToken.get(), TokenElevation, &te, sizeof(te), &len)) {
		runningElevated = te.TokenIsElevated ? true : false;
	}
	return runningElevated;
}
