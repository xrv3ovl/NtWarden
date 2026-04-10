#include "pch.h"
#include "SymbolHelper.h"
#include "LoggerView.h"

#include <DbgHelp.h>
#include <dia2.h>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <winhttp.h>
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "diaguids.lib")
#pragma comment(lib, "winhttp.lib")

namespace {
	const wchar_t* SymTagToString(DWORD tag) {
		switch (tag) {
		case 5:  return L"Function";
		case 7:  return L"Data";
		case 10: return L"PublicSymbol";
		case 11: return L"UDT";
		case 12: return L"Enum";
		case 17: return L"Typedef";
		default: return L"Other";
		}
	}

	struct SymEnumContext {
		std::vector<SymbolEntry>* Symbols;
		DWORD64 ModBase;
	};

	BOOL CALLBACK EnumSymbolsProc(PSYMBOL_INFOW pSymInfo, ULONG SymbolSize, PVOID UserContext) {
		UNREFERENCED_PARAMETER(SymbolSize);
		auto* ctx = static_cast<SymEnumContext*>(UserContext);

		SymbolEntry entry;
		entry.Name = pSymInfo->Name;
		entry.Address = pSymInfo->Address;
		entry.Size = static_cast<ULONG>(pSymInfo->Size);
		entry.Tag = static_cast<SymbolTag>(pSymInfo->Tag);
		entry.TagName = SymTagToString(pSymInfo->Tag);

		ctx->Symbols->push_back(std::move(entry));
		return TRUE;
	}

	BOOL CALLBACK EnumTypesProc(PSYMBOL_INFOW pSymInfo, ULONG SymbolSize, PVOID UserContext) {
		UNREFERENCED_PARAMETER(SymbolSize);
		auto* ctx = static_cast<SymEnumContext*>(UserContext);

		SymbolEntry entry;
		entry.Name = pSymInfo->Name;
		entry.Address = pSymInfo->Address;
		entry.Size = static_cast<ULONG>(pSymInfo->Size);
		entry.Tag = static_cast<SymbolTag>(pSymInfo->Tag);
		entry.TagName = SymTagToString(pSymInfo->Tag);
		ctx->Symbols->push_back(std::move(entry));
		return TRUE;
	}

	const char* ModuleSymTypeToString(DWORD symType) {
		switch (symType) {
		case SymPdb:    return "PDB";
		case SymDia:    return "DIA";
		case SymCv:     return "CodeView";
		case SymSym:    return "SYM";
		case SymExport: return "Export";
		case SymDeferred:return "Deferred";
		case SymNone:   return "None";
		default:        return "Other";
		}
	}

	bool HasTypeInfo(HANDLE hProcess, DWORD64 moduleBase, const wchar_t* typeName) {
		const size_t allocSize = sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(wchar_t);
		auto* symInfo = static_cast<SYMBOL_INFOW*>(malloc(allocSize));
		if (!symInfo)
			return false;

		memset(symInfo, 0, allocSize);
		symInfo->SizeOfStruct = sizeof(SYMBOL_INFOW);
		symInfo->MaxNameLen = MAX_SYM_NAME;
		const bool ok = !!SymGetTypeFromNameW(hProcess, moduleBase, typeName, symInfo);
		free(symInfo);
		return ok;
	}

	std::wstring NormalizeImagePath(std::wstring imagePath) {
		if (imagePath.find(L"\\SystemRoot\\") == 0) {
			wchar_t winDir[MAX_PATH]{};
			GetWindowsDirectoryW(winDir, MAX_PATH);
			imagePath = winDir + imagePath.substr(11);
		}
		else if (imagePath.find(L"\\??\\") == 0) {
			imagePath = imagePath.substr(4);
		}
		return imagePath;
	}

	SymbolTag DiaSymTagToSymbolTag(DWORD tag) {
		switch (tag) {
		case SymTagFunction: return SymbolTag::Function;
		case SymTagData: return SymbolTag::Data;
		case SymTagUDT: return SymbolTag::UDT;
		case SymTagEnum: return SymbolTag::Enum;
		case SymTagTypedef: return SymbolTag::Typedef;
		case SymTagPublicSymbol: return SymbolTag::PublicSymbol;
		default: return SymbolTag::Null;
		}
	}

	const wchar_t* DiaSymTagToString(DWORD tag) {
		switch (tag) {
		case SymTagFunction: return L"Function";
		case SymTagData: return L"Data";
		case SymTagUDT: return L"UDT";
		case SymTagEnum: return L"Enum";
		case SymTagTypedef: return L"Typedef";
		case SymTagPublicSymbol: return L"PublicSymbol";
		default: return L"Other";
		}
	}

	std::wstring GetTypeNameFromTypeIndex(HANDLE hProcess, DWORD64 moduleBase, ULONG typeIndex) {
		WCHAR* typeName = nullptr;
		if (SymGetTypeInfo(hProcess, moduleBase, typeIndex, TI_GET_SYMNAME, &typeName) && typeName) {
			std::wstring name(typeName);
			LocalFree(typeName);
			return name;
		}
		return {};
	}

	const wchar_t* BasicTypeToString(DWORD baseType, ULONG64 length) {
		switch (baseType) {
		case btVoid: return L"void";
		case btChar: return L"char";
		case btWChar: return L"wchar_t";
		case btBool: return L"bool";
		case btInt:
			switch (length) {
			case 1: return L"char";
			case 2: return L"short";
			case 4: return L"int";
			case 8: return L"__int64";
			default: return L"int";
			}
		case btUInt:
			switch (length) {
			case 1: return L"unsigned char";
			case 2: return L"unsigned short";
			case 4: return L"unsigned int";
			case 8: return L"unsigned __int64";
			default: return L"unsigned int";
			}
		case btLong: return length == 8 ? L"long long" : L"long";
		case btULong: return length == 8 ? L"unsigned long long" : L"unsigned long";
		case btFloat:
			switch (length) {
			case 4: return L"float";
			case 8: return L"double";
			default: return L"float";
			}
		case btHresult: return L"HRESULT";
		default: return nullptr;
		}
	}

	std::wstring FormatTypeName(HANDLE hProcess, DWORD64 moduleBase, ULONG typeIndex) {
		DWORD symTag = 0;
		if (!SymGetTypeInfo(hProcess, moduleBase, typeIndex, TI_GET_SYMTAG, &symTag))
			return {};

		switch (symTag) {
		case SymTagBaseType: {
			DWORD baseType = 0;
			ULONG64 length = 0;
			SymGetTypeInfo(hProcess, moduleBase, typeIndex, TI_GET_BASETYPE, &baseType);
			SymGetTypeInfo(hProcess, moduleBase, typeIndex, TI_GET_LENGTH, &length);
			if (auto name = BasicTypeToString(baseType, length); name)
				return name;
			return L"<base>";
		}

		case SymTagPointerType: {
			ULONG pointeeType = 0;
			if (SymGetTypeInfo(hProcess, moduleBase, typeIndex, TI_GET_TYPEID, &pointeeType)) {
				auto inner = FormatTypeName(hProcess, moduleBase, pointeeType);
				if (!inner.empty())
					return inner + L"*";
			}
			return L"void*";
		}

		case SymTagArrayType: {
			ULONG elemType = 0;
			ULONG count = 0;
			ULONG64 totalLength = 0;
			SymGetTypeInfo(hProcess, moduleBase, typeIndex, TI_GET_TYPEID, &elemType);
			SymGetTypeInfo(hProcess, moduleBase, typeIndex, TI_GET_COUNT, &count);
			SymGetTypeInfo(hProcess, moduleBase, typeIndex, TI_GET_LENGTH, &totalLength);
			auto inner = FormatTypeName(hProcess, moduleBase, elemType);
			if (count != 0)
				return inner + L"[" + std::to_wstring(count) + L"]";
			if (totalLength != 0)
				return inner + L"[]";
			return inner.empty() ? L"<array>" : inner + L"[]";
		}

		case SymTagTypedef:
		case SymTagUDT:
		case SymTagEnum:
		case SymTagFunctionType: {
			auto name = GetTypeNameFromTypeIndex(hProcess, moduleBase, typeIndex);
			if (!name.empty())
				return name;
			return symTag == SymTagEnum ? L"<enum>" : (symTag == SymTagUDT ? L"<udt>" : L"<type>");
		}

		case SymTagBaseClass: {
			ULONG baseClassType = 0;
			if (SymGetTypeInfo(hProcess, moduleBase, typeIndex, TI_GET_TYPEID, &baseClassType))
				return FormatTypeName(hProcess, moduleBase, baseClassType);
			return L"<base class>";
		}

		default: {
			auto name = GetTypeNameFromTypeIndex(hProcess, moduleBase, typeIndex);
			if (!name.empty())
				return name;
			return {};
		}
		}
	}
}

// CV_INFO structures for parsing PE debug directory
#pragma pack(push, 1)
struct CV_INFO_PDB70 {
	DWORD CvSignature;  // 'RSDS'
	GUID  Signature;
	DWORD Age;
	char  PdbFileName[1]; // variable length
};
struct CV_INFO_PDB20 {
	DWORD CvHeader;
	DWORD Offset;
	DWORD Signature;
	DWORD Age;
	char  PdbFileName[1];
};
#pragma pack(pop)

// Download a file from HTTPS URL to a local path using WinHTTP.
static bool HttpDownloadFile(const std::wstring& url, const std::wstring& localPath) {
	// Parse URL
	URL_COMPONENTS urlComp = {};
	urlComp.dwStructSize = sizeof(urlComp);
	wchar_t hostName[256] = {};
	wchar_t urlPath[1024] = {};
	urlComp.lpszHostName = hostName;
	urlComp.dwHostNameLength = _countof(hostName);
	urlComp.lpszUrlPath = urlPath;
	urlComp.dwUrlPathLength = _countof(urlPath);

	if (!WinHttpCrackUrl(url.c_str(), 0, 0, &urlComp))
		return false;

	HINTERNET hSession = WinHttpOpen(L"NtWarden/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
	if (!hSession)
		return false;

	HINTERNET hConnect = WinHttpConnect(hSession, hostName, urlComp.nPort, 0);
	if (!hConnect) {
		WinHttpCloseHandle(hSession);
		return false;
	}

	HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", urlPath, nullptr,
		WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
	if (!hRequest) {
		WinHttpCloseHandle(hConnect);
		WinHttpCloseHandle(hSession);
		return false;
	}

	if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
		!WinHttpReceiveResponse(hRequest, nullptr)) {
		WinHttpCloseHandle(hRequest);
		WinHttpCloseHandle(hConnect);
		WinHttpCloseHandle(hSession);
		return false;
	}

	DWORD statusCode = 0;
	DWORD statusSize = sizeof(statusCode);
	WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
		WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX);

	if (statusCode != 200) {
		WinHttpCloseHandle(hRequest);
		WinHttpCloseHandle(hConnect);
		WinHttpCloseHandle(hSession);
		return false;
	}

	std::ofstream file(localPath, std::ios::binary | std::ios::trunc);
	if (!file) {
		WinHttpCloseHandle(hRequest);
		WinHttpCloseHandle(hConnect);
		WinHttpCloseHandle(hSession);
		return false;
	}

	BYTE buffer[8192];
	DWORD bytesRead = 0;
	while (WinHttpReadData(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
		file.write(reinterpret_cast<char*>(buffer), bytesRead);
		bytesRead = 0;
	}

	file.close();
	WinHttpCloseHandle(hRequest);
	WinHttpCloseHandle(hConnect);
	WinHttpCloseHandle(hSession);
	return true;
}

// Parse PE debug directory to extract PDB GUID, age, and filename.
static bool GetPdbInfoFromPE(const std::wstring& peFilePath, GUID& pdbGuid, DWORD& pdbAge, std::string& pdbFileName) {
	HANDLE hFile = CreateFileW(peFilePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hFile == INVALID_HANDLE_VALUE)
		return false;

	HANDLE hMapping = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
	if (!hMapping) {
		CloseHandle(hFile);
		return false;
	}

	auto* base = static_cast<BYTE*>(MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0));
	if (!base) {
		CloseHandle(hMapping);
		CloseHandle(hFile);
		return false;
	}

	bool result = false;
	auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
	if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
		auto* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dosHeader->e_lfanew);
		if (ntHeaders->Signature == IMAGE_NT_SIGNATURE) {
			DWORD debugDirRVA = 0;
			DWORD debugDirSize = 0;

			if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
				auto* opt64 = reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(&ntHeaders->OptionalHeader);
				debugDirRVA = opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
				debugDirSize = opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
			}
			else {
				auto* opt32 = reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(&ntHeaders->OptionalHeader);
				debugDirRVA = opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
				debugDirSize = opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
			}

			if (debugDirRVA && debugDirSize) {
				// Convert RVA to file offset using section headers
				auto* sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
				DWORD debugDirFileOffset = 0;
				for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
					if (debugDirRVA >= sectionHeader[i].VirtualAddress &&
						debugDirRVA < sectionHeader[i].VirtualAddress + sectionHeader[i].Misc.VirtualSize) {
						debugDirFileOffset = debugDirRVA - sectionHeader[i].VirtualAddress + sectionHeader[i].PointerToRawData;
						break;
					}
				}

				if (debugDirFileOffset) {
					DWORD numEntries = debugDirSize / sizeof(IMAGE_DEBUG_DIRECTORY);
					auto* debugDir = reinterpret_cast<IMAGE_DEBUG_DIRECTORY*>(base + debugDirFileOffset);

					for (DWORD i = 0; i < numEntries; i++) {
						if (debugDir[i].Type == IMAGE_DEBUG_TYPE_CODEVIEW && debugDir[i].SizeOfData >= sizeof(CV_INFO_PDB70)) {
							auto* cvInfo = reinterpret_cast<CV_INFO_PDB70*>(base + debugDir[i].PointerToRawData);
							if (cvInfo->CvSignature == 'SDSR') { // RSDS
								pdbGuid = cvInfo->Signature;
								pdbAge = cvInfo->Age;
								pdbFileName = cvInfo->PdbFileName;
								result = true;
								break;
							}
						}
					}
				}
			}
		}
	}

	UnmapViewOfFile(base);
	CloseHandle(hMapping);
	CloseHandle(hFile);
	return result;
}

// Download PDB from Microsoft symbol server for a given PE file.
std::wstring SymbolHelper::DownloadPdb(const std::wstring& peFilePath, const std::wstring& localCacheDir) {
	GUID pdbGuid;
	DWORD pdbAge;
	std::string pdbFileNameA;

	if (!GetPdbInfoFromPE(peFilePath, pdbGuid, pdbAge, pdbFileNameA)) {
		LoggerView::AddLog(LoggerView::UserModeLog, "PDB: Failed to parse debug info from PE");
		return {};
	}

	// Build GUID+Age signature string: {GUID}{Age} with no dashes, uppercase hex
	wchar_t sig[128];
	swprintf_s(sig, L"%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%X",
		pdbGuid.Data1, pdbGuid.Data2, pdbGuid.Data3,
		pdbGuid.Data4[0], pdbGuid.Data4[1], pdbGuid.Data4[2], pdbGuid.Data4[3],
		pdbGuid.Data4[4], pdbGuid.Data4[5], pdbGuid.Data4[6], pdbGuid.Data4[7],
		pdbAge);

	std::wstring pdbFileName(pdbFileNameA.begin(), pdbFileNameA.end());

	// Local cache path: <cacheDir>/<pdbname>/<signature>/<pdbname>
	std::wstring localDir = localCacheDir + L"\\" + pdbFileName + L"\\" + sig;
	std::wstring localFile = localDir + L"\\" + pdbFileName;

	// Check if already cached
	if (GetFileAttributesW(localFile.c_str()) != INVALID_FILE_ATTRIBUTES) {
		LoggerView::AddLog(LoggerView::UserModeLog, "PDB: Using cached PDB at %ws", localFile.c_str());
		return localFile;
	}

	// Create directory
	std::error_code ec;
	std::filesystem::create_directories(localDir, ec);
	if (ec) {
		LoggerView::AddLog(LoggerView::UserModeLog, "PDB: Failed to create cache directory");
		return {};
	}

	// Build download URL
	std::wstring url = std::wstring(L"https://msdl.microsoft.com/download/symbols/") +
		pdbFileName + L"/" + sig + L"/" + pdbFileName;

	LoggerView::AddLog(LoggerView::UserModeLog, "PDB: Downloading from symbol server...");

	if (HttpDownloadFile(url, localFile)) {
		auto fileSize = std::filesystem::file_size(localFile, ec);
		if (!ec && fileSize > 0) {
			LoggerView::AddLog(LoggerView::UserModeLog, "PDB: Downloaded successfully (%llu bytes)", (unsigned long long)fileSize);
			return localFile;
		}
		// Empty file — download failed silently
		std::filesystem::remove(localFile, ec);
	}

	LoggerView::AddLog(LoggerView::UserModeLog, "PDB: Download failed. Trying compressed PDB (_)...");

	// Try compressed PDB: replace last char of filename with '_'
	std::wstring compressedName = pdbFileName;
	if (compressedName.size() > 0)
		compressedName.back() = L'_';
	std::wstring compressedUrl = std::wstring(L"https://msdl.microsoft.com/download/symbols/") +
		pdbFileName + L"/" + sig + L"/" + compressedName;
	std::wstring compressedLocal = localDir + L"\\" + compressedName;

	if (HttpDownloadFile(compressedUrl, compressedLocal)) {
		auto fileSize = std::filesystem::file_size(compressedLocal, ec);
		if (!ec && fileSize > 0) {
			// Decompress using expand.exe
			std::wstring expandCmd = L"expand \"" + compressedLocal + L"\" \"" + localFile + L"\"";
			int ret = _wsystem(expandCmd.c_str());
			std::filesystem::remove(compressedLocal, ec);
			if (ret == 0 && GetFileAttributesW(localFile.c_str()) != INVALID_FILE_ATTRIBUTES) {
				LoggerView::AddLog(LoggerView::UserModeLog, "PDB: Decompressed successfully");
				return localFile;
			}
		}
		std::filesystem::remove(compressedLocal, ec);
	}

	LoggerView::AddLog(LoggerView::UserModeLog, "PDB: All download attempts failed");
	return {};
}

std::wstring SymbolHelper::DownloadPdbBySignature(const GUID& pdbGuid, DWORD pdbAge, const char* pdbFileNameA, const std::wstring& localCacheDir) {
	wchar_t sig[128];
	swprintf_s(sig, L"%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%X",
		pdbGuid.Data1, pdbGuid.Data2, pdbGuid.Data3,
		pdbGuid.Data4[0], pdbGuid.Data4[1], pdbGuid.Data4[2], pdbGuid.Data4[3],
		pdbGuid.Data4[4], pdbGuid.Data4[5], pdbGuid.Data4[6], pdbGuid.Data4[7],
		pdbAge);

	std::wstring pdbFileName(pdbFileNameA, pdbFileNameA + strlen(pdbFileNameA));

	std::wstring localDir = localCacheDir + L"\\" + pdbFileName + L"\\" + sig;
	std::wstring localFile = localDir + L"\\" + pdbFileName;

	if (GetFileAttributesW(localFile.c_str()) != INVALID_FILE_ATTRIBUTES) {
		LoggerView::AddLog(LoggerView::UserModeLog, "PDB: Using cached PDB at %ws", localFile.c_str());
		return localFile;
	}

	std::error_code ec;
	std::filesystem::create_directories(localDir, ec);
	if (ec) {
		LoggerView::AddLog(LoggerView::UserModeLog, "PDB: Failed to create cache directory");
		return {};
	}

	std::wstring url = std::wstring(L"https://msdl.microsoft.com/download/symbols/") +
		pdbFileName + L"/" + sig + L"/" + pdbFileName;

	LoggerView::AddLog(LoggerView::UserModeLog, "PDB: Downloading from symbol server (remote signature)...");

	if (HttpDownloadFile(url, localFile)) {
		auto fileSize = std::filesystem::file_size(localFile, ec);
		if (!ec && fileSize > 0) {
			LoggerView::AddLog(LoggerView::UserModeLog, "PDB: Downloaded successfully (%llu bytes)", (unsigned long long)fileSize);
			return localFile;
		}
		std::filesystem::remove(localFile, ec);
	}

	LoggerView::AddLog(LoggerView::UserModeLog, "PDB: Download failed. Trying compressed PDB (_)...");

	std::wstring compressedName = pdbFileName;
	if (compressedName.size() > 0)
		compressedName.back() = L'_';
	std::wstring compressedUrl = std::wstring(L"https://msdl.microsoft.com/download/symbols/") +
		pdbFileName + L"/" + sig + L"/" + compressedName;
	std::wstring compressedLocal = localDir + L"\\" + compressedName;

	if (HttpDownloadFile(compressedUrl, compressedLocal)) {
		auto fileSize = std::filesystem::file_size(compressedLocal, ec);
		if (!ec && fileSize > 0) {
			std::wstring expandCmd = L"expand \"" + compressedLocal + L"\" \"" + localFile + L"\"";
			int ret = _wsystem(expandCmd.c_str());
			std::filesystem::remove(compressedLocal, ec);
			if (ret == 0 && GetFileAttributesW(localFile.c_str()) != INVALID_FILE_ATTRIBUTES) {
				LoggerView::AddLog(LoggerView::UserModeLog, "PDB: Decompressed successfully");
				return localFile;
			}
		}
		std::filesystem::remove(compressedLocal, ec);
	}

	LoggerView::AddLog(LoggerView::UserModeLog, "PDB: All download attempts failed (remote signature)");
	return {};
}

static void InitSymbolEngine(HANDLE hProcess, bool& initialized) {
	DWORD options = SymGetOptions();
	options |= SYMOPT_UNDNAME | SYMOPT_AUTO_PUBLICS | SYMOPT_DEFERRED_LOADS;
	SymSetOptions(options);

	// No symbol server path — we download PDBs ourselves and load from local files
	if (SymInitializeW(hProcess, nullptr, FALSE)) {
		initialized = true;
		LoggerView::AddLog(LoggerView::UserModeLog, "Symbol engine initialized (handle=0x%p)", hProcess);
	}
	else {
		auto err = GetLastError();
		CStringA msg;
		msg.Format("SymInitialize failed: 0x%08X (handle=0x%p)", err, hProcess);
		LoggerView::AddLog(LoggerView::UserModeLog, msg);
	}
}

SymbolHelper::SymbolHelper() {
	_hProcess = GetCurrentProcess();
	InitSymbolEngine(_hProcess, _initialized);
}

SymbolHelper::SymbolHelper(HANDLE customHandle) {
	_hProcess = customHandle;
	InitSymbolEngine(_hProcess, _initialized);
}

SymbolHelper::~SymbolHelper() {
	if (_initialized) {
		SymCleanup(_hProcess);
	}
}

bool SymbolHelper::LoadSymbolsForModule(LoadedModuleInfo& module) {
	if (!_initialized)
		return false;

	module.Loading = true;
	module.SymbolStatus = L"Loading...";
	module.ExactPdbLoaded = false;

	auto imagePath = NormalizeImagePath(module.FullPath);
	module.PdbPath.clear();

	wchar_t tempPath[MAX_PATH]{};
	if (GetTempPathW(_countof(tempPath), tempPath) != 0) {
		std::wstring symbolCacheDir = std::wstring(tempPath) + L"NtWardenSymbols";
		module.PdbPath = DownloadPdb(imagePath, symbolCacheDir);
		if (!module.PdbPath.empty() &&
			LoadSymbolsFromPdb(module.PdbPath, module.Name.c_str(), module.BaseAddress, module.ImageSize)) {
			module.SymbolsLoaded = true;
			module.ExactPdbLoaded = true;
			module.Loading = false;
			module.SymbolStatus = L"PDB loaded";
			LoggerView::AddLog(LoggerView::UserModeLog, "Symbols loaded from exact PDB for %ws", module.Name.c_str());
			return true;
		}
	}

	auto base = SymLoadModuleExW(
		_hProcess, nullptr, imagePath.c_str(), nullptr,
		module.BaseAddress, module.ImageSize, nullptr, 0
	);

	if (base == 0) {
		auto err = GetLastError();
		if (err == ERROR_SUCCESS) {
			module.SymbolsLoaded = true;
			module.Loading = false;
			module.SymbolStatus = L"Loaded (cached)";
			return true;
		}
		CStringA msg;
		msg.Format("SymLoadModuleEx failed for %ws: 0x%08X", module.Name.c_str(), err);
		LoggerView::AddLog(LoggerView::UserModeLog, msg);
		module.Loading = false;
		module.SymbolStatus = L"Failed to load";
		return false;
	}

	IMAGEHLP_MODULEW64 modInfo{};
	modInfo.SizeOfStruct = sizeof(modInfo);
	if (SymGetModuleInfoW64(_hProcess, base, &modInfo)) {
		switch (modInfo.SymType) {
		case SymNone:    module.SymbolStatus = L"No symbols"; break;
		case SymPdb:     module.SymbolStatus = L"PDB loaded"; break;
		case SymExport:  module.SymbolStatus = L"Export symbols only"; break;
		case SymDeferred:module.SymbolStatus = L"Deferred"; break;
		default:         module.SymbolStatus = L"Loaded"; break;
		}

		CStringA diagMsg;
		diagMsg.Format("Symbol diag for %ws: SymType=%d, PDB='%ws', ImageName='%ws', LoadedImageName='%ws'",
			module.Name.c_str(), (int)modInfo.SymType,
			modInfo.LoadedPdbName, modInfo.ImageName, modInfo.LoadedImageName);
		LoggerView::AddLog(LoggerView::UserModeLog, diagMsg);
	}

	module.SymbolsLoaded = true;
	module.Loading = false;

	CStringA msg;
	msg.Format("Symbols loaded for %ws: %ws", module.Name.c_str(), module.SymbolStatus.c_str());
	LoggerView::AddLog(LoggerView::UserModeLog, msg);
	return true;
}

bool SymbolHelper::LoadSymbolsFromPdb(const std::wstring& pdbPath, const wchar_t* moduleName, DWORD64 baseAddress, DWORD imageSize) {
	if (!_initialized)
		return false;

	CStringA pdbPathA(pdbPath.c_str());

	auto base = SymLoadModuleEx(
		_hProcess, nullptr, pdbPathA.GetString(), nullptr,
		baseAddress, imageSize, nullptr, 0
	);

	if (base == 0 && GetLastError() != ERROR_SUCCESS) {
		CStringA msg;
		msg.Format("SymLoadModuleEx failed for PDB '%ws': 0x%08X", pdbPath.c_str(), GetLastError());
		LoggerView::AddLog(LoggerView::UserModeLog, msg);
		return false;
	}

	IMAGEHLP_MODULE64 modInfo{};
	modInfo.SizeOfStruct = sizeof(modInfo);
	auto loadedBase = base ? base : baseAddress;
	bool hasModuleInfo = !!SymGetModuleInfo64(_hProcess, loadedBase, &modInfo);
	bool hasEprocess = HasTypeInfo(_hProcess, loadedBase, L"_EPROCESS");
	bool hasObjectType = HasTypeInfo(_hProcess, loadedBase, L"_OBJECT_TYPE");
	bool usableSymBackend = hasModuleInfo && (modInfo.SymType == SymPdb || modInfo.SymType == SymDia);

	if (hasModuleInfo) {
		LoggerView::AddLog(
			LoggerView::UserModeLog,
			"PDB loaded for %ws: backend=%s, EPROCESS=%s, OBJECT_TYPE=%s, PDB='%s'",
			moduleName,
			ModuleSymTypeToString(modInfo.SymType),
			hasEprocess ? "yes" : "no",
			hasObjectType ? "yes" : "no",
			modInfo.LoadedPdbName);
	}
	else {
		LoggerView::AddLog(
			LoggerView::UserModeLog,
			"PDB loaded for %ws, but module info query failed: 0x%08X",
			moduleName,
			GetLastError());
	}

	return usableSymBackend || hasEprocess || hasObjectType;
}

void SymbolHelper::UnloadModule(DWORD64 baseAddress) {
	if (_initialized)
		SymUnloadModule64(_hProcess, baseAddress);
}

ULONG SymbolHelper::GetStructMemberOffset(DWORD64 moduleBase, const wchar_t* typeName, const wchar_t* memberName) {
	if (!_initialized)
		return (ULONG)-1;

	// Allocate SYMBOL_INFOW with space for name
	const size_t allocSize = sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(wchar_t);
	SYMBOL_INFOW* symInfo = (SYMBOL_INFOW*)malloc(allocSize);
	if (!symInfo)
		return (ULONG)-1;

	memset(symInfo, 0, allocSize);
	symInfo->SizeOfStruct = sizeof(SYMBOL_INFOW);
	symInfo->MaxNameLen = MAX_SYM_NAME;

	if (!SymGetTypeFromNameW(_hProcess, moduleBase, typeName, symInfo)) {
		free(symInfo);
		return (ULONG)-1;
	}

	DWORD typeIndex = symInfo->TypeIndex;
	free(symInfo);

	// Get children count
	DWORD childrenCount = 0;
	if (!SymGetTypeInfo(_hProcess, moduleBase, typeIndex, TI_GET_CHILDRENCOUNT, &childrenCount) || childrenCount == 0)
		return (ULONG)-1;

	// Allocate TI_FINDCHILDREN_PARAMS
	size_t childSize = sizeof(TI_FINDCHILDREN_PARAMS) + childrenCount * sizeof(ULONG);
	TI_FINDCHILDREN_PARAMS* children = (TI_FINDCHILDREN_PARAMS*)malloc(childSize);
	if (!children)
		return (ULONG)-1;

	memset(children, 0, childSize);
	children->Count = childrenCount;
	children->Start = 0;

	if (!SymGetTypeInfo(_hProcess, moduleBase, typeIndex, TI_FINDCHILDREN, children)) {
		free(children);
		return (ULONG)-1;
	}

	ULONG offset = (ULONG)-1;
	for (ULONG i = 0; i < childrenCount; i++) {
		WCHAR* name = nullptr;
		if (SymGetTypeInfo(_hProcess, moduleBase, children->ChildId[i], TI_GET_SYMNAME, &name) && name) {
			if (_wcsicmp(name, memberName) == 0) {
				DWORD memberOffset = 0;
				if (SymGetTypeInfo(_hProcess, moduleBase, children->ChildId[i], TI_GET_OFFSET, &memberOffset))
					offset = memberOffset;
				LocalFree(name);
				break;
			}
			LocalFree(name);
		}
	}

	free(children);
	return offset;
}

DWORD64 SymbolHelper::GetSymbolAddressFromName(DWORD64 moduleBase, const wchar_t* symbolName) {
	if (!_initialized)
		return 0;

	const size_t allocSize = sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(wchar_t);
	SYMBOL_INFOW* symInfo = (SYMBOL_INFOW*)malloc(allocSize);
	if (!symInfo)
		return 0;

	memset(symInfo, 0, allocSize);
	symInfo->SizeOfStruct = sizeof(SYMBOL_INFOW);
	symInfo->MaxNameLen = MAX_SYM_NAME;

	if (!SymFromNameW(_hProcess, symbolName, symInfo)) {
		free(symInfo);
		return 0;
	}

	DWORD64 addr = symInfo->Address;
	free(symInfo);
	return addr;
}

bool SymbolHelper::GetSymbolNameFromAddress(DWORD64 address, std::string& nameOut, DWORD64& displacementOut) {
	nameOut.clear();
	displacementOut = 0;
	if (!_initialized || address == 0)
		return false;

	const size_t allocSize = sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(char);
	SYMBOL_INFO* symInfo = (SYMBOL_INFO*)malloc(allocSize);
	if (!symInfo)
		return false;

	memset(symInfo, 0, allocSize);
	symInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
	symInfo->MaxNameLen = MAX_SYM_NAME;

	DWORD64 displacement = 0;
	if (!SymFromAddr(_hProcess, address, &displacement, symInfo)) {
		free(symInfo);
		return false;
	}

	nameOut.assign(symInfo->Name, symInfo->NameLen);
	displacementOut = displacement;
	free(symInfo);
	return true;
}

ULONG SymbolHelper::GetStructSize(DWORD64 moduleBase, const wchar_t* typeName) {
	if (!_initialized)
		return 0;

	const size_t allocSize = sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(wchar_t);
	SYMBOL_INFOW* symInfo = (SYMBOL_INFOW*)malloc(allocSize);
	if (!symInfo)
		return 0;

	memset(symInfo, 0, allocSize);
	symInfo->SizeOfStruct = sizeof(SYMBOL_INFOW);
	symInfo->MaxNameLen = MAX_SYM_NAME;

	if (!SymGetTypeFromNameW(_hProcess, moduleBase, typeName, symInfo)) {
		free(symInfo);
		return 0;
	}

	ULONG size = (ULONG)symInfo->Size;
	free(symInfo);
	return size;
}

std::vector<SymbolEntry> SymbolHelper::EnumerateSymbols(const LoadedModuleInfo& module) {
	std::vector<SymbolEntry> symbols;
	if (!_initialized || !module.SymbolsLoaded)
		return symbols;

	SymEnumContext ctx;
	ctx.Symbols = &symbols;
	ctx.ModBase = module.BaseAddress;

	SymEnumSymbolsW(_hProcess, module.BaseAddress, L"*", EnumSymbolsProc, &ctx);

	std::sort(symbols.begin(), symbols.end(),
		[](const SymbolEntry& a, const SymbolEntry& b) { return a.Address < b.Address; });

	CStringA msg;
	msg.Format("Enumerated %zu symbols from %ws", symbols.size(), module.Name.c_str());
	LoggerView::AddLog(LoggerView::UserModeLog, msg);

	return symbols;
}

std::vector<SymbolEntry> SymbolHelper::EnumerateTypes(const LoadedModuleInfo& module) {
	std::vector<SymbolEntry> symbols;
	if (!_initialized || !module.SymbolsLoaded)
		return symbols;

	if (!module.PdbPath.empty()) {
		CComPtr<IDiaDataSource> source;
		if (SUCCEEDED(source.CoCreateInstance(__uuidof(DiaSource)))) {
			if (SUCCEEDED(source->loadDataFromPdb(module.PdbPath.c_str()))) {
				CComPtr<IDiaSession> session;
				if (SUCCEEDED(source->openSession(&session)) && session) {
					CComPtr<IDiaSymbol> global;
					if (SUCCEEDED(session->get_globalScope(&global)) && global) {
						for (DWORD diaTag : { SymTagUDT, SymTagEnum, SymTagTypedef }) {
							CComPtr<IDiaEnumSymbols> enumerator;
							if (SUCCEEDED(global->findChildren((enum SymTagEnum)diaTag, nullptr, nsNone, &enumerator)) && enumerator) {
								while (true) {
									CComPtr<IDiaSymbol> symbol;
									ULONG fetched = 0;
									if (FAILED(enumerator->Next(1, &symbol, &fetched)) || fetched == 0)
										break;

									CComBSTR name;
									if (FAILED(symbol->get_name(&name)) || name == nullptr)
										continue;

									ULONGLONG size = 0;
									symbol->get_length(&size);

									SymbolEntry entry;
									entry.Name = static_cast<const wchar_t*>(name);
									entry.Address = 0;
									entry.Size = static_cast<ULONG>(size);
									entry.Tag = DiaSymTagToSymbolTag(diaTag);
									entry.TagName = DiaSymTagToString(diaTag);
									symbols.push_back(std::move(entry));
								}
							}
						}
					}
				}
			}
		}
		if (!symbols.empty()) {
			std::sort(symbols.begin(), symbols.end(),
				[](const SymbolEntry& a, const SymbolEntry& b) { return a.Name < b.Name; });
			LoggerView::AddLog(LoggerView::UserModeLog, "Enumerated %zu DIA types from %ws", symbols.size(), module.Name.c_str());
			return symbols;
		}
	}

	SymEnumContext ctx;
	ctx.Symbols = &symbols;
	ctx.ModBase = module.BaseAddress;

	SymEnumTypesW(_hProcess, module.BaseAddress, EnumTypesProc, &ctx);

	std::sort(symbols.begin(), symbols.end(),
		[](const SymbolEntry& a, const SymbolEntry& b) { return a.Name < b.Name; });

	LoggerView::AddLog(LoggerView::UserModeLog, "Enumerated %zu types from %ws", symbols.size(), module.Name.c_str());
	return symbols;
}

std::vector<TypeMemberEntry> SymbolHelper::EnumerateTypeMembers(DWORD64 moduleBase, const wchar_t* typeName) {
	std::vector<TypeMemberEntry> members;
	if (!_initialized)
		return members;

	const size_t allocSize = sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(wchar_t);
	auto* symInfo = static_cast<SYMBOL_INFOW*>(malloc(allocSize));
	if (!symInfo)
		return members;

	memset(symInfo, 0, allocSize);
	symInfo->SizeOfStruct = sizeof(SYMBOL_INFOW);
	symInfo->MaxNameLen = MAX_SYM_NAME;

	if (!SymGetTypeFromNameW(_hProcess, moduleBase, typeName, symInfo)) {
		free(symInfo);
		return members;
	}

	DWORD typeIndex = symInfo->TypeIndex;
	free(symInfo);

	DWORD childrenCount = 0;
	if (!SymGetTypeInfo(_hProcess, moduleBase, typeIndex, TI_GET_CHILDRENCOUNT, &childrenCount) || childrenCount == 0)
		return members;

	size_t childSize = sizeof(TI_FINDCHILDREN_PARAMS) + childrenCount * sizeof(ULONG);
	auto* children = static_cast<TI_FINDCHILDREN_PARAMS*>(malloc(childSize));
	if (!children)
		return members;

	memset(children, 0, childSize);
	children->Count = childrenCount;
	children->Start = 0;
	if (!SymGetTypeInfo(_hProcess, moduleBase, typeIndex, TI_FINDCHILDREN, children)) {
		free(children);
		return members;
	}

	members.reserve(childrenCount);
	for (ULONG i = 0; i < childrenCount; i++) {
		TypeMemberEntry entry;
		WCHAR* name = nullptr;
		if (SymGetTypeInfo(_hProcess, moduleBase, children->ChildId[i], TI_GET_SYMNAME, &name) && name) {
			entry.Name = name;
			LocalFree(name);
		}
		DWORD offset = 0;
		if (SymGetTypeInfo(_hProcess, moduleBase, children->ChildId[i], TI_GET_OFFSET, &offset))
			entry.Offset = offset;
		ULONG64 length = 0;
		if (SymGetTypeInfo(_hProcess, moduleBase, children->ChildId[i], TI_GET_LENGTH, &length))
			entry.Size = static_cast<ULONG>(length);
		ULONG typeId = 0;
		if (SymGetTypeInfo(_hProcess, moduleBase, children->ChildId[i], TI_GET_TYPEID, &typeId))
			entry.TypeName = FormatTypeName(_hProcess, moduleBase, typeId);
		BOOL bitField = FALSE;
		if (SymGetTypeInfo(_hProcess, moduleBase, children->ChildId[i], TI_GET_BITPOSITION, &bitField) && bitField) {
			DWORD bits = 0;
			if (SymGetTypeInfo(_hProcess, moduleBase, children->ChildId[i], TI_GET_LENGTH, &bits))
				entry.TypeName += L" : " + std::to_wstring(bits);
		}
		DWORD tag = 0;
		if (SymGetTypeInfo(_hProcess, moduleBase, children->ChildId[i], TI_GET_SYMTAG, &tag)) {
			entry.Tag = static_cast<SymbolTag>(tag);
			entry.TagName = SymTagToString(tag);
		}
		if (!entry.Name.empty())
			members.push_back(std::move(entry));
	}

	free(children);
	std::sort(members.begin(), members.end(), [](const auto& a, const auto& b) {
		return a.Offset < b.Offset;
	});
	return members;
}
