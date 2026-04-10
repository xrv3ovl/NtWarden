#pragma once

#include "ViewBase.h"
#include "UserHooksView.h"
#include <vector>
#include <string>
#include <memory>
#include <future>
#include <mutex>

class ProcessSecurityView : public ViewBase {
public:
	ProcessSecurityView();
	void BuildWindow();
	void RefreshNow();
	void SetTargetPid(DWORD pid);
	bool HasPendingAsync() const;

private:
	enum class Section {
		UnbackedMemory,
		Hollowing,
		ModuleStomping,
		DirectSyscalls,
		SyscallStubs,
		UserHooks,
		Tokens,
		DebugObjects,
		Hypervisor,
		JobObjects,
		CfgStatus,
	};

	/* ---- Common ---- */
	void BuildToolBar();
	DWORD _targetPid{ 0 };
	bool _scanning{ false };
	std::string _scanStatus;
	Section _activeSection{ Section::UnbackedMemory };

	/* ---- Unbacked Memory Scanner ---- */
	struct UnbackedMemEntry {
		unsigned long long BaseAddress{ 0 };
		unsigned long long RegionSize{ 0 };
		unsigned long Protect{ 0 };
		unsigned long State{ 0 };
		unsigned long Type{ 0 };
		bool IsExecutable{ false };
		bool IsPrivate{ false };
		std::string Details;
	};
	void ScanUnbackedMemory(DWORD pid);
	std::vector<UnbackedMemEntry> _unbackedMem;
	void BuildUnbackedMemTable();
	std::future<std::vector<UnbackedMemEntry>> _unbackedFuture;
	bool _unbackedScanning{ false };

	/* ---- Process Hollowing Detection ---- */
	struct HollowingResult {
		unsigned long long PebImageBase{ 0 };
		unsigned long long ActualImageBase{ 0 };
		std::string ImagePath;
		bool Mismatched{ false };
		bool Scanned{ false };
	};
	void ScanHollowing(DWORD pid);
	HollowingResult _hollowing;
	void BuildHollowingPanel();
	std::future<HollowingResult> _hollowingFuture;
	bool _hollowingScanning{ false };

	/* ---- Module Stomping Detection ---- */
	struct StompedSection {
		std::string ModuleName;
		std::string SectionName;
		unsigned long long MemoryAddress{ 0 };
		unsigned long SectionSize{ 0 };
		unsigned long PatchedBytes{ 0 };
		bool IsPatched{ false };
	};
	void ScanModuleStomping(DWORD pid);
	std::vector<StompedSection> _stompedSections;
	void BuildModuleStompingTable();
	std::future<std::vector<StompedSection>> _stompingFuture;
	bool _stompingScanning{ false };

	/* ---- Direct Syscall Detection ---- */
	struct DirectSyscallEntry {
		unsigned long long Address{ 0 };
		std::string Module;
		std::string Context;
		std::string Disassembly;
		unsigned long long RegionBase{ 0 };
		unsigned long RegionSize{ 0 };
		unsigned long Protect{ 0 };
		unsigned char Bytes[24]{};
		unsigned int ByteCount{ 0 };
		bool OutsideNtdll{ true };
	};
	void ScanDirectSyscalls(DWORD pid);
	std::vector<DirectSyscallEntry> _directSyscalls;
	void BuildDirectSyscallTable();
	void BuildDirectSyscallDetails();
	std::future<std::vector<DirectSyscallEntry>> _syscallFuture;
	bool _syscallScanning{ false };
	int _selectedDirectSyscall{ -1 };
	int _disasmDirectSyscall{ -1 };
	bool _showDirectSyscallDisasm{ false };

	/* ---- Syscall Stub Integrity Check ---- */
	struct SyscallStubEntry {
		std::string FunctionName;
		unsigned long ServiceNumber{ 0 };
		unsigned long long Address{ 0 };
		unsigned char MemoryBytes[16]{};
		unsigned char DiskBytes[16]{};
		bool IsPatched{ false };
	};
	void ScanSyscallStubs(DWORD pid);
	std::vector<SyscallStubEntry> _syscallStubs;
	void BuildSyscallStubTable();
	std::future<std::vector<SyscallStubEntry>> _stubFuture;
	bool _stubScanning{ false };

	/* ---- Token Manipulation Detection ---- */
	struct TokenInfo {
		unsigned long ProcessId{ 0 };
		std::string ImageName;
		std::string UserName;
		unsigned long SessionId{ 0 };
		unsigned long long TokenAddress{ 0 };
		unsigned long IntegrityLevel{ 0 };
		std::string IntegrityString;
		bool IsElevated{ false };
		bool IsImpersonating{ false };
		std::vector<std::string> Privileges;
		std::vector<std::string> EnabledPrivileges;
		bool SuspiciousPrivileges{ false };
	};
	void ScanTokens(DWORD pid);
	TokenInfo _tokenInfo;
	void BuildTokenPanel();
	std::future<TokenInfo> _tokenFuture;
	bool _tokenScanning{ false };

	/* ---- Debug Object Detection ---- */
	struct DebugObjectEntry {
		unsigned long ProcessId{ 0 };
		std::string ImageName;
		bool HasDebugObject{ false };
		bool HasDebugPort{ false };
	};
	void ScanDebugObjects();
	std::vector<DebugObjectEntry> _debugObjects;
	void BuildDebugObjectTable();
	std::future<std::vector<DebugObjectEntry>> _debugFuture;
	bool _debugScanning{ false };

	/* ---- Hypervisor Presence Detection ---- */
	struct HypervisorInfo {
		bool HypervisorPresent{ false };
		std::string VendorId;
		bool TimingAnomaly{ false };
		unsigned long long AvgRdtscCycles{ 0 };
		unsigned long long AvgCpuidCycles{ 0 };
		bool Scanned{ false };
	};
	void ScanHypervisor();
	HypervisorInfo _hypervisorInfo;
	void BuildHypervisorPanel();

	/* ---- Job Object Inspector ---- */
	struct JobObjectInfo {
		unsigned long ProcessId{ 0 };
		std::string ImageName;
		bool InJob{ false };
		unsigned long ActiveProcesses{ 0 };
		unsigned long TotalProcesses{ 0 };
		unsigned long long ProcessMemoryLimit{ 0 };
		unsigned long long JobMemoryLimit{ 0 };
		unsigned long ActiveProcessLimit{ 0 };
		unsigned long UIRestrictions{ 0 };
		bool HasCpuRateLimit{ false };
		bool HasNetRateLimit{ false };
	};
	void ScanJobObjects(DWORD pid);
	JobObjectInfo _jobInfo;
	void BuildJobObjectPanel();
	std::future<JobObjectInfo> _jobFuture;
	bool _jobScanning{ false };

	/* ---- CFG Status ---- */
	struct CfgInfo {
		unsigned long ProcessId{ 0 };
		bool CfgEnabled{ false };
		bool CfgStrictMode{ false };
		bool CfgExportSuppression{ false };
		bool XfgEnabled{ false };
		bool XfgAuditMode{ false };
		unsigned long MitigationFlags{ 0 };
		unsigned long MitigationFlags2{ 0 };
		bool Scanned{ false };
	};
	void ScanCfgStatus(DWORD pid);
	CfgInfo _cfgInfo;
	void BuildCfgPanel();
	std::future<CfgInfo> _cfgFuture;
	bool _cfgScanning{ false };

	UserHooksView _userHooksView;
};
