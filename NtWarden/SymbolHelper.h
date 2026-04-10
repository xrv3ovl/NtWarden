#pragma once

#include "StructureModel.h"

#include <string>
#include <vector>
#include <unordered_map>
#include <functional>

struct LoadedModuleInfo {
	std::wstring Name;
	std::wstring FullPath;
	std::wstring PdbPath;
	DWORD64 BaseAddress{ 0 };
	DWORD ImageSize{ 0 };
	bool SymbolsLoaded{ false };
	bool ExactPdbLoaded{ false };
	bool Loading{ false };
	std::wstring SymbolStatus;
};

enum class SymbolTag : DWORD {
	Null = 0,
	Function = 5,
	Data = 7,
	PublicSymbol = 10,
	UDT = 11,
	Enum = 12,
	Typedef = 17,
};

struct SymbolEntry {
	std::wstring Name;
	DWORD64 Address{ 0 };
	ULONG Size{ 0 };
	SymbolTag Tag{ SymbolTag::Null };
	std::wstring TagName;
};

struct TypeMemberEntry {
	std::wstring Name;
	std::wstring TypeName;
	ULONG Offset{ 0 };
	ULONG Size{ 0 };
	SymbolTag Tag{ SymbolTag::Null };
	std::wstring TagName;
};

class SymbolHelper {
public:
	SymbolHelper();
	explicit SymbolHelper(HANDLE customHandle);
	~SymbolHelper();

	SymbolHelper(const SymbolHelper&) = delete;
	SymbolHelper& operator=(const SymbolHelper&) = delete;

	bool IsInitialized() const { return _initialized; }

	bool LoadSymbolsForModule(LoadedModuleInfo& module);
	bool LoadSymbolsFromPdb(const std::wstring& pdbPath, const wchar_t* moduleName, DWORD64 baseAddress, DWORD imageSize);
	void UnloadModule(DWORD64 baseAddress);

	// Download PDB from Microsoft symbol server for a given PE file.
	// Returns local path to PDB, or empty string on failure.
	static std::wstring DownloadPdb(const std::wstring& peFilePath, const std::wstring& localCacheDir);

	// Download PDB using pre-extracted signature (for remote scenarios where PE is not local).
	static std::wstring DownloadPdbBySignature(const GUID& pdbGuid, DWORD pdbAge, const char* pdbFileName, const std::wstring& localCacheDir);

	std::vector<SymbolEntry> EnumerateSymbols(const LoadedModuleInfo& module);
	std::vector<SymbolEntry> EnumerateTypes(const LoadedModuleInfo& module);
	std::vector<TypeMemberEntry> EnumerateTypeMembers(DWORD64 moduleBase, const wchar_t* typeName);

	// PDB-based struct offset resolution
	ULONG GetStructMemberOffset(DWORD64 moduleBase, const wchar_t* typeName, const wchar_t* memberName);
	DWORD64 GetSymbolAddressFromName(DWORD64 moduleBase, const wchar_t* symbolName);
	ULONG GetStructSize(DWORD64 moduleBase, const wchar_t* typeName);

	// Reverse lookup: address -> nearest symbol. Returns true on success.
	bool GetSymbolNameFromAddress(DWORD64 address, std::string& nameOut, DWORD64& displacementOut);

private:
	HANDLE _hProcess{ nullptr };
	bool _initialized{ false };
};
