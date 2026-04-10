#pragma once

#include "DriverHelper.h"
#include "SymbolHelper.h"
#include "ViewBase.h"
#include <memory>
#include <future>

class ProcessObjectsView : public ViewBase {
public:
	ProcessObjectsView();
	void BuildWindow();
	void RefreshProcesses();

private:
	void BuildToolBar();
	void BuildTable();
	void BuildDetailsPanel();
	void BuildCrossCheckPanel();
	void DoSort(int col, bool asc);
	void ResolveEprocessOffsets();
	void RunCrossCheck();

	static const char* ProtectionSignerToString(unsigned char signer);
	static const char* ProtectionTypeToString(unsigned char type);

	struct ProcessRow {
		unsigned long long EprocessAddress{ 0 };
		unsigned long ProcessId{ 0 };
		unsigned long ParentProcessId{ 0 };
		unsigned long SessionId{ 0 };
		unsigned long HandleCount{ 0 };
		unsigned long ThreadCount{ 0 };
		long long CreateTime{ 0 };
		std::string ImageName;
		bool IsProtected{ false };
		bool IsProtectedLight{ false };
		bool IsWow64{ false };
		bool Filtered{ false };
		/* PDB-resolved fields */
		unsigned long long TokenAddress{ 0 };
		unsigned long long PebAddress{ 0 };
		unsigned long long DirectoryTableBase{ 0 };
		unsigned long long ObjectTableAddress{ 0 };
		unsigned long Flags{ 0 };
		unsigned long Flags2{ 0 };
		unsigned char SignatureLevel{ 0 };
		unsigned char SectionSignatureLevel{ 0 };
		unsigned char ProtectionType{ 0 };
		unsigned char ProtectionSigner{ 0 };
		unsigned long MitigationFlags{ 0 };
		unsigned long MitigationFlags2{ 0 };
		unsigned char Protection{ 0 };
	};

	std::vector<std::shared_ptr<ProcessRow>> _processes;
	std::shared_ptr<ProcessRow> _selectedProcess;
	const ImGuiTableColumnSortSpecs* _specs = nullptr;
	bool _loaded{ false };

	// PDB symbol resolution (async)
	struct PdbResult {
		bool resolved{ false };
		bool hasDetailedFields{ false };
		std::string status;
	};
	static PdbResult ResolveEprocessOffsetsAsync();
	std::future<PdbResult> _pdbFuture;
	std::unique_ptr<SymbolHelper> _symbolHelper;
	bool _pdbOffsetsResolved{ false };
	bool _pdbResolutionAttempted{ false };
	bool _pdbResolving{ false };
	bool _pdbHasDetailedFields{ false };
	std::string _pdbStatus;

	// DKOM Cross-Check state (async)
	std::future<DriverHelper::CrossCheckResult> _crossCheckFuture;
	struct CrossCheckRow {
		unsigned long ProcessId{ 0 };
		unsigned long long EprocessAddress{ 0 };
		std::string ImageName;
		unsigned char Sources{ 0 };
	};
	std::vector<CrossCheckRow> _crossCheckEntries;
	CROSS_CHECK_RESULT _crossCheckHeader{};
	bool _crossCheckRan{ false };
	bool _crossCheckRunning{ false };
	bool _showCrossCheck{ false };
	std::string _crossCheckStatus;
};
