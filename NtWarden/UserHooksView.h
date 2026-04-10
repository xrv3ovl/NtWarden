#pragma once

#include "ViewBase.h"
#include "LoggerView.h"
#include <vector>
#include <string>
#include <memory>
#include <future>
#include <mutex>
#include <unordered_map>

class UserHooksView : public ViewBase {
public:
	UserHooksView();
	void BuildWindow();
	void RefreshNow();
	void SetTargetPid(DWORD pid);
	bool HasPendingAsync() const;

	enum class HookType {
		IAT,
		EAT,
		Inline,
		InlineRedirect,
		PatchedPrologue
	};

	static const char* HookTypeToString(HookType type) {
		switch (type) {
		case HookType::IAT: return "IAT";
		case HookType::EAT: return "EAT";
		case HookType::Inline: return "Inline";
		case HookType::InlineRedirect: return "Inline Redirect";
		case HookType::PatchedPrologue: return "Patched Prologue";
		default: return "Unknown";
		}
	}

private:
	void BuildToolBar();
	void BuildTable();
	void BuildDetailsPanel();
	void DoSort(int col, bool asc);
	void ScanProcess(DWORD pid);

	struct HookEntry {
		HookType Type{ HookType::IAT };
		std::string Module;
		std::string Function;
		unsigned long long OriginalAddress{ 0 };
		unsigned long long HookedAddress{ 0 };
		std::string HookTarget;        // module owning the hooked address
		std::string Details;
		std::string Disassembly;
		unsigned char Bytes[16]{};
		unsigned int ByteCount{ 0 };
		bool Suspicious{ true };
	};

	struct ScanResult {
		std::vector<std::shared_ptr<HookEntry>> hooks;
		int suspiciousCount{ 0 };
		std::string status;
	};

	// Signature cache: module base name (lowercase) -> is Microsoft-signed
	using SignatureCache = std::unordered_map<std::string, bool>;

	static ScanResult ScanProcessAsync(DWORD pid);
	static bool IsMicrosoftSigned(const std::string& filePath);
	static bool IsTargetMicrosoftSigned(HANDLE hProcess, const std::string& targetModule, SignatureCache& sigCache);
	static void ScanModuleIATStatic(HANDLE hProcess, HMODULE hModule, const std::string& moduleName,
		BYTE* localImage, SIZE_T imageSize, ScanResult& result, SignatureCache& sigCache);
	static void ScanModuleEATStatic(HANDLE hProcess, HMODULE hModule, const std::string& moduleName,
		BYTE* localImage, SIZE_T imageSize, ScanResult& result, SignatureCache& sigCache);
	static void ScanModuleInlineStatic(HANDLE hProcess, HMODULE hModule, const std::string& moduleName,
		BYTE* localImage, SIZE_T imageSize, ScanResult& result, SignatureCache& sigCache);

	std::vector<std::shared_ptr<HookEntry>> _hooks;
	std::shared_ptr<HookEntry> _selectedHook;
	std::shared_ptr<HookEntry> _disasmHook;
	const ImGuiTableColumnSortSpecs* _specs = nullptr;
	DWORD _targetPid{ 0 };
	bool _scanning{ false };
	bool _scanned{ false };
	bool _showDisasmPopup{ false };
	int _suspiciousCount{ 0 };
	std::string _scanStatus;

	// Async scan
	std::future<ScanResult> _scanFuture;
};
