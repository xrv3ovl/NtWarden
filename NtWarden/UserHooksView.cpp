#include "pch.h"
#include "imgui.h"
#include "UserHooksView.h"
#include <algorithm>
#include "SortHelper.h"
#include "ImGuiExt.h"
#include <capstone/capstone.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <wincrypt.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

using namespace ImGui;

namespace {
	std::string FormatBytes(const unsigned char* bytes, unsigned int count) {
		char buffer[16 * 3 + 1]{};
		char* cursor = buffer;
		for (unsigned int i = 0; i < count && i < 16; i++) {
			int written = sprintf_s(cursor, buffer + sizeof(buffer) - cursor, "%02X ", bytes[i]);
			if (written <= 0)
				break;
			cursor += written;
		}
		if (cursor != buffer && *(cursor - 1) == ' ')
			*(cursor - 1) = '\0';
		return buffer;
	}

	std::string DisassembleBytes(const unsigned char* bytes, unsigned int count, unsigned long long address) {
		if (!bytes || count == 0)
			return {};

		csh handle{};
#ifdef _WIN64
		const cs_mode mode = CS_MODE_64;
#else
		const cs_mode mode = CS_MODE_32;
#endif
		auto err = cs_open(CS_ARCH_X86, mode, &handle);
		if (err != CS_ERR_OK)
			return "Capstone initialization failed";

		cs_insn* insn = nullptr;
		size_t insnCount = cs_disasm(handle, bytes, count, address, 0, &insn);
		if (insnCount == 0) {
			cs_close(&handle);
			return "Unable to disassemble bytes";
		}

		std::string text;
		for (size_t i = 0; i < insnCount; i++) {
			char line[256]{};
			sprintf_s(line, "0x%016llX: %-8s %s",
				static_cast<unsigned long long>(insn[i].address),
				insn[i].mnemonic,
				insn[i].op_str);
			if (!text.empty())
				text += "\n";
			text += line;
		}

		cs_free(insn, insnCount);
		cs_close(&handle);
		return text;
	}

	std::string AnnotateDisassemblyTarget(const std::string& disassembly,
		unsigned long long targetAddress, const std::string& targetModule) {
		if (disassembly.empty() || targetAddress == 0 || targetModule.empty())
			return disassembly;

		char target64[32]{};
		char target32[24]{};
		sprintf_s(target64, "0x%llx", targetAddress);
		sprintf_s(target32, "0x%X", static_cast<unsigned int>(targetAddress & 0xFFFFFFFF));

		std::string annotated = disassembly;
		size_t lineStart = 0;
		while (lineStart < annotated.size()) {
			size_t lineEnd = annotated.find('\n', lineStart);
			if (lineEnd == std::string::npos)
				lineEnd = annotated.size();

			std::string line = annotated.substr(lineStart, lineEnd - lineStart);
			if (line.find(target64) != std::string::npos || line.find(target32) != std::string::npos) {
				annotated.insert(lineEnd, " ; " + targetModule);
				break;
			}

			lineStart = lineEnd + 1;
		}
		return annotated;
	}

	bool IsExecutableRva(BYTE* imageBase, SIZE_T imageSize, DWORD rva) {
		if (!imageBase || rva >= imageSize)
			return false;

		auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(imageBase);
		if (dos->e_magic != IMAGE_DOS_SIGNATURE)
			return false;

		auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(imageBase + dos->e_lfanew);
		if (nt->Signature != IMAGE_NT_SIGNATURE)
			return false;

		auto* section = IMAGE_FIRST_SECTION(nt);
		for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
			DWORD sectionStart = section[i].VirtualAddress;
			DWORD sectionSize = section[i].Misc.VirtualSize ? section[i].Misc.VirtualSize : section[i].SizeOfRawData;
			DWORD sectionEnd = sectionStart + sectionSize;
			if (rva >= sectionStart && rva < sectionEnd)
				return (section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
		}

		return false;
	}
}

UserHooksView::UserHooksView() : ViewBase(0) {}

void UserHooksView::SetTargetPid(DWORD pid) {
	_targetPid = pid;
}

/*
 * Resolve which module owns a given address in a remote process.
 */
static std::string ResolveModuleForAddress(HANDLE hProcess, ULONG_PTR address) {
	HMODULE modules[1024];
	DWORD cbNeeded = 0;
	if (!EnumProcessModulesEx(hProcess, modules, sizeof(modules), &cbNeeded, LIST_MODULES_ALL))
		return {};

	DWORD count = cbNeeded / sizeof(HMODULE);
	for (DWORD i = 0; i < count; i++) {
		MODULEINFO mi{};
		if (!GetModuleInformation(hProcess, modules[i], &mi, sizeof(mi)))
			continue;
		auto start = (ULONG_PTR)mi.lpBaseOfDll;
		auto end = start + mi.SizeOfImage;
		if (address >= start && address < end) {
			char name[MAX_PATH]{};
			if (GetModuleBaseNameA(hProcess, modules[i], name, MAX_PATH))
				return name;
			return "<unknown>";
		}
	}
	return "<outside all modules>";
}

/*
 * Load the on-disk version of a module for comparison.
 * Returns a heap-allocated buffer (caller must free) and sets imageSize.
 */
static BYTE* LoadDiskImage(HANDLE hProcess, HMODULE hModule, SIZE_T& outSize) {
	outSize = 0;
	char path[MAX_PATH]{};
	if (!GetModuleFileNameExA(hProcess, hModule, path, MAX_PATH))
		return nullptr;

	HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hFile == INVALID_HANDLE_VALUE)
		return nullptr;

	DWORD fileSize = GetFileSize(hFile, nullptr);
	if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
		CloseHandle(hFile);
		return nullptr;
	}

	HANDLE hMapping = CreateFileMappingA(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
	CloseHandle(hFile);
	if (!hMapping)
		return nullptr;

	auto* mappedBase = (BYTE*)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
	CloseHandle(hMapping);
	if (!mappedBase)
		return nullptr;

	/* Parse PE to get SizeOfImage */
	auto* dos = (IMAGE_DOS_HEADER*)mappedBase;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
		UnmapViewOfFile(mappedBase);
		return nullptr;
	}

	auto* nt = (IMAGE_NT_HEADERS*)(mappedBase + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE) {
		UnmapViewOfFile(mappedBase);
		return nullptr;
	}

	SIZE_T imageSize = nt->OptionalHeader.SizeOfImage;
	auto* image = (BYTE*)VirtualAlloc(nullptr, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!image) {
		UnmapViewOfFile(mappedBase);
		return nullptr;
	}

	/* Copy headers */
	memcpy(image, mappedBase, nt->OptionalHeader.SizeOfHeaders);

	/* Copy sections */
	auto* section = IMAGE_FIRST_SECTION(nt);
	for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
		if (section[i].SizeOfRawData == 0 || section[i].PointerToRawData == 0)
			continue;
		if (section[i].PointerToRawData + section[i].SizeOfRawData > fileSize)
			continue;
		if (section[i].VirtualAddress + section[i].SizeOfRawData > imageSize)
			continue;
		memcpy(image + section[i].VirtualAddress,
			mappedBase + section[i].PointerToRawData,
			section[i].SizeOfRawData);
	}

	UnmapViewOfFile(mappedBase);
	outSize = imageSize;
	return image;
}

/*
 * Check if a PE file is signed by Microsoft.
 * Uses WinVerifyTrust for signature validation, then inspects the signer name.
 */
bool UserHooksView::IsMicrosoftSigned(const std::string& filePath) {
	if (filePath.empty())
		return false;

	// Convert to wide string
	int wlen = MultiByteToWideChar(CP_ACP, 0, filePath.c_str(), -1, nullptr, 0);
	if (wlen <= 0) return false;
	std::vector<wchar_t> wpath(wlen);
	MultiByteToWideChar(CP_ACP, 0, filePath.c_str(), -1, wpath.data(), wlen);

	// First verify the file has a valid signature
	GUID actionId = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	WINTRUST_FILE_INFO fileInfo{};
	fileInfo.cbStruct = sizeof(fileInfo);
	fileInfo.pcwszFilePath = wpath.data();

	WINTRUST_DATA wtd{};
	wtd.cbStruct = sizeof(wtd);
	wtd.dwUIChoice = WTD_UI_NONE;
	wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
	wtd.dwUnionChoice = WTD_CHOICE_FILE;
	wtd.pFile = &fileInfo;
	wtd.dwStateAction = WTD_STATEACTION_VERIFY;
	wtd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

	LONG trustResult = WinVerifyTrust(nullptr, &actionId, &wtd);

	bool isMicrosoft = false;

	if (trustResult == ERROR_SUCCESS || trustResult == CERT_E_EXPIRED ||
		trustResult == CERT_E_CHAINING) {
		// Extract signer info from the state data
		CRYPT_PROVIDER_DATA* provData = WTHelperProvDataFromStateData(wtd.hWVTStateData);
		if (provData) {
			CRYPT_PROVIDER_SGNR* signer = WTHelperGetProvSignerFromChain(provData, 0, FALSE, 0);
			if (signer && signer->csCertChain > 0) {
				CRYPT_PROVIDER_CERT* cert = WTHelperGetProvCertFromChain(signer, 0);
				if (cert && cert->pCert) {
					// Get the subject name from the certificate
					char subjectName[512]{};
					CertNameToStrA(cert->pCert->dwCertEncodingType,
						&cert->pCert->pCertInfo->Subject,
						CERT_X500_NAME_STR, subjectName, sizeof(subjectName));

					// Check for Microsoft in the organization name
					std::string subject(subjectName);
					std::string subjectLower = subject;
					std::transform(subjectLower.begin(), subjectLower.end(), subjectLower.begin(), ::tolower);
					if (subjectLower.find("o=microsoft") != std::string::npos)
						isMicrosoft = true;
				}
			}
		}
	}

	// Close the state handle
	wtd.dwStateAction = WTD_STATEACTION_CLOSE;
	WinVerifyTrust(nullptr, &actionId, &wtd);

	// If embedded signature check didn't find Microsoft, try the catalog (for OS files)
	if (!isMicrosoft) {
		HANDLE hCatAdmin = nullptr;
		if (CryptCATAdminAcquireContext(&hCatAdmin, nullptr, 0)) {
			HANDLE hFile = CreateFileW(wpath.data(), GENERIC_READ, FILE_SHARE_READ,
				nullptr, OPEN_EXISTING, 0, nullptr);
			if (hFile != INVALID_HANDLE_VALUE) {
				DWORD hashSize = 0;
				CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, nullptr, 0);
				if (hashSize > 0) {
					std::vector<BYTE> hash(hashSize);
					if (CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, hash.data(), 0)) {
						HANDLE hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash.data(), hashSize, 0, nullptr);
						if (hCatInfo) {
							// File is in a catalog — Windows catalog-signed files are Microsoft
							isMicrosoft = true;
							CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
						}
					}
				}
				CloseHandle(hFile);
			}
			CryptCATAdminReleaseContext(hCatAdmin, 0);
		}
	}

	return isMicrosoft;
}

/*
 * Check if a target module is Microsoft-signed, using a cache for efficiency.
 */
bool UserHooksView::IsTargetMicrosoftSigned(HANDLE hProcess, const std::string& targetModule, SignatureCache& sigCache) {
	if (targetModule.empty() || targetModule == "<outside all modules>" || targetModule == "<unknown>")
		return false;

	// Normalize key to lowercase
	std::string key = targetModule;
	std::transform(key.begin(), key.end(), key.begin(), ::tolower);

	auto it = sigCache.find(key);
	if (it != sigCache.end())
		return it->second;

	// Resolve target module base name to full path
	HMODULE modules[1024];
	DWORD cbNeeded = 0;
	bool result = false;
	if (EnumProcessModulesEx(hProcess, modules, sizeof(modules), &cbNeeded, LIST_MODULES_ALL)) {
		DWORD count = cbNeeded / sizeof(HMODULE);
		for (DWORD i = 0; i < count; i++) {
			char name[MAX_PATH]{};
			if (!GetModuleBaseNameA(hProcess, modules[i], name, MAX_PATH))
				continue;
			std::string nameLower = name;
			std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);
			if (nameLower == key) {
				char fullPath[MAX_PATH]{};
				if (GetModuleFileNameExA(hProcess, modules[i], fullPath, MAX_PATH)) {
					result = IsMicrosoftSigned(fullPath);
				}
				break;
			}
		}
	}

	sigCache[key] = result;
	return result;
}

void UserHooksView::ScanModuleIATStatic(HANDLE hProcess, HMODULE hModule, const std::string& moduleName,
	BYTE* localImage, SIZE_T imageSize, ScanResult& result, SignatureCache& sigCache) {

	auto* dos = (IMAGE_DOS_HEADER*)localImage;
	auto* nt = (IMAGE_NT_HEADERS*)(localImage + dos->e_lfanew);

	DWORD importRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	DWORD importSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	if (importRVA == 0 || importSize == 0)
		return;
	if (importRVA >= imageSize)
		return;

	auto* importDesc = (IMAGE_IMPORT_DESCRIPTOR*)(localImage + importRVA);

	for (; importDesc->Name != 0; importDesc++) {
		if (importDesc->Name >= imageSize)
			break;

		const char* dllName = (const char*)(localImage + importDesc->Name);

		DWORD thunkRVA = importDesc->FirstThunk;
		DWORD origThunkRVA = importDesc->OriginalFirstThunk;
		if (thunkRVA == 0)
			continue;

		/* Read the actual IAT entries from the remote process */
		auto* origThunk = origThunkRVA ? (IMAGE_THUNK_DATA*)(localImage + origThunkRVA) : nullptr;
		ULONG_PTR iatAddr = (ULONG_PTR)hModule + thunkRVA;

		for (DWORD idx = 0; ; idx++) {
			/* Read actual IAT entry from remote process memory */
			ULONG_PTR actualAddr = 0;
			SIZE_T bytesRead = 0;
			if (!ReadProcessMemory(hProcess, (LPCVOID)(iatAddr + idx * sizeof(ULONG_PTR)),
				&actualAddr, sizeof(actualAddr), &bytesRead))
				break;
			if (actualAddr == 0)
				break;

			/* Get function name from OriginalFirstThunk (hint/name table) */
			std::string funcName;
			if (origThunk && origThunkRVA) {
				ULONG_PTR origThunkOffset = origThunkRVA + idx * sizeof(IMAGE_THUNK_DATA);
				if (origThunkOffset + sizeof(IMAGE_THUNK_DATA) <= imageSize) {
					auto* ot = (IMAGE_THUNK_DATA*)(localImage + origThunkOffset);
					if (!(ot->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
						DWORD hintNameRVA = (DWORD)(ot->u1.AddressOfData);
						if (hintNameRVA + sizeof(IMAGE_IMPORT_BY_NAME) < imageSize) {
							auto* hint = (IMAGE_IMPORT_BY_NAME*)(localImage + hintNameRVA);
							funcName = (const char*)hint->Name;
						}
					}
					else {
						char ordBuf[32];
						sprintf_s(ordBuf, "Ordinal#%llu", (unsigned long long)(ot->u1.Ordinal & 0xFFFF));
						funcName = ordBuf;
					}
				}
			}
			if (funcName.empty()) {
				char ordBuf[32];
				sprintf_s(ordBuf, "Entry#%u", idx);
				funcName = ordBuf;
			}

			/* Check: does the actual address point into the expected DLL? */
			std::string targetModule = ResolveModuleForAddress(hProcess, actualAddr);

			/* Compare: the IAT entry should resolve to the imported DLL */
			std::string expectedDll = dllName;
			/* Normalize for comparison - strip .dll extension, lowercase */
			std::string expectedLower = expectedDll;
			std::transform(expectedLower.begin(), expectedLower.end(), expectedLower.begin(), ::tolower);
			if (expectedLower.size() > 4 && expectedLower.substr(expectedLower.size() - 4) == ".dll")
				expectedLower = expectedLower.substr(0, expectedLower.size() - 4);

			std::string targetLower = targetModule;
			std::transform(targetLower.begin(), targetLower.end(), targetLower.begin(), ::tolower);
			if (targetLower.size() > 4 && targetLower.substr(targetLower.size() - 4) == ".dll")
				targetLower = targetLower.substr(0, targetLower.size() - 4);

			/*
			 * Skip API set shims — these are virtual DLLs that always redirect legitimately.
			 */
			if (targetLower.find("api-ms-win-") == 0 || expectedLower.find("api-ms-win-") == 0)
				continue;
			if (targetLower.find("ext-ms-win-") == 0 || expectedLower.find("ext-ms-win-") == 0)
				continue;

			if (targetLower != expectedLower && !targetModule.empty()) {
				/*
				 * IAT points to a different module than expected.
				 * Legitimate forwarding (advapi32->ntdll, user32->win32u, etc.)
				 * always targets Microsoft-signed modules — skip those entirely.
				 */
				bool targetSigned = IsTargetMicrosoftSigned(hProcess, targetModule, sigCache);
				if (targetSigned)
					continue;

				auto hook = std::make_shared<HookEntry>();
				hook->Type = HookType::IAT;
				hook->Module = moduleName;
				hook->Function = std::string(dllName) + "!" + funcName;
				hook->OriginalAddress = 0;
				hook->HookedAddress = actualAddr;
				hook->HookTarget = targetModule;
				hook->Details = "IAT entry points to " + targetModule + " instead of " + dllName;
				hook->Suspicious = true;
				result.hooks.push_back(std::move(hook));
				result.suspiciousCount++;
			}
		}
	}
}

void UserHooksView::ScanModuleEATStatic(HANDLE hProcess, HMODULE hModule, const std::string& moduleName,
	BYTE* localImage, SIZE_T imageSize, ScanResult& result, SignatureCache& sigCache) {

	auto* dos = (IMAGE_DOS_HEADER*)localImage;
	auto* nt = (IMAGE_NT_HEADERS*)(localImage + dos->e_lfanew);

	DWORD exportRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	DWORD exportSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	if (exportRVA == 0 || exportSize == 0)
		return;
	if (exportRVA >= imageSize)
		return;

	auto* exportDir = (IMAGE_EXPORT_DIRECTORY*)(localImage + exportRVA);
	if (exportDir->NumberOfFunctions == 0)
		return;
	if (exportDir->AddressOfFunctions >= imageSize)
		return;

	auto* diskFunctions = (DWORD*)(localImage + exportDir->AddressOfFunctions);
	auto* diskNames = exportDir->AddressOfNames && exportDir->AddressOfNames < imageSize
		? (DWORD*)(localImage + exportDir->AddressOfNames) : nullptr;
	auto* diskOrdinals = exportDir->AddressOfNameOrdinals && exportDir->AddressOfNameOrdinals < imageSize
		? (WORD*)(localImage + exportDir->AddressOfNameOrdinals) : nullptr;

	/* Read the actual EAT from the remote process */
	DWORD eatSize = exportDir->NumberOfFunctions * sizeof(DWORD);
	std::vector<DWORD> remoteFunctions(exportDir->NumberOfFunctions, 0);
	SIZE_T bytesRead = 0;
	ULONG_PTR remoteEatAddr = (ULONG_PTR)hModule + exportDir->AddressOfFunctions;
	if (!ReadProcessMemory(hProcess, (LPCVOID)remoteEatAddr, remoteFunctions.data(), eatSize, &bytesRead))
		return;

	for (DWORD i = 0; i < exportDir->NumberOfFunctions; i++) {
		DWORD diskRVA = diskFunctions[i];
		DWORD remoteRVA = remoteFunctions[i];

		if (diskRVA == 0 && remoteRVA == 0)
			continue;

		/* Skip forwarded exports (RVA falls within the export directory) */
		if (diskRVA >= exportRVA && diskRVA < exportRVA + exportSize)
			continue;

		if (diskRVA != remoteRVA) {
			/* Resolve function name */
			std::string funcName;
			if (diskNames && diskOrdinals) {
				for (DWORD n = 0; n < exportDir->NumberOfNames; n++) {
					if (diskOrdinals[n] == i) {
						DWORD nameRVA = diskNames[n];
						if (nameRVA < imageSize)
							funcName = (const char*)(localImage + nameRVA);
						break;
					}
				}
			}
			if (funcName.empty()) {
				char buf[32];
				sprintf_s(buf, "Ordinal#%u", i + exportDir->Base);
				funcName = buf;
			}

			ULONG_PTR hookedAbsolute = (ULONG_PTR)hModule + remoteRVA;
			std::string targetModule = ResolveModuleForAddress(hProcess, hookedAbsolute);

			/* Skip legitimate Microsoft-signed DLL redirections */
			bool targetSigned = IsTargetMicrosoftSigned(hProcess, targetModule, sigCache);
			if (targetSigned)
				continue;

			auto hook = std::make_shared<HookEntry>();
			hook->Type = HookType::EAT;
			hook->Module = moduleName;
			hook->Function = funcName;
			hook->OriginalAddress = (ULONG_PTR)hModule + diskRVA;
			hook->HookedAddress = hookedAbsolute;
			hook->HookTarget = targetModule;
			char detail[128];
			sprintf_s(detail, "EAT RVA changed: 0x%08X -> 0x%08X", diskRVA, remoteRVA);
			hook->Details = detail;
			hook->Suspicious = true;
			result.hooks.push_back(std::move(hook));
			result.suspiciousCount++;
		}
	}
}

void UserHooksView::ScanModuleInlineStatic(HANDLE hProcess, HMODULE hModule, const std::string& moduleName,
	BYTE* localImage, SIZE_T imageSize, ScanResult& result, SignatureCache& sigCache) {

	auto* dos = (IMAGE_DOS_HEADER*)localImage;
	auto* nt = (IMAGE_NT_HEADERS*)(localImage + dos->e_lfanew);

	DWORD exportRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	DWORD exportSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	if (exportRVA == 0 || exportSize == 0)
		return;
	if (exportRVA >= imageSize)
		return;

	auto* exportDir = (IMAGE_EXPORT_DIRECTORY*)(localImage + exportRVA);
	if (exportDir->NumberOfFunctions == 0)
		return;
	if (exportDir->AddressOfFunctions >= imageSize)
		return;

	auto* diskFunctions = (DWORD*)(localImage + exportDir->AddressOfFunctions);
	auto* diskNames = exportDir->AddressOfNames && exportDir->AddressOfNames < imageSize
		? (DWORD*)(localImage + exportDir->AddressOfNames) : nullptr;
	auto* diskOrdinals = exportDir->AddressOfNameOrdinals && exportDir->AddressOfNameOrdinals < imageSize
		? (WORD*)(localImage + exportDir->AddressOfNameOrdinals) : nullptr;

	/* Check prologue of each exported function for JMP/CALL patches */
	constexpr SIZE_T PROLOGUE_SIZE = 16; // check first 16 bytes

	for (DWORD i = 0; i < exportDir->NumberOfFunctions; i++) {
		DWORD rva = diskFunctions[i];
		if (rva == 0)
			continue;
		/* Skip forwarded exports */
		if (rva >= exportRVA && rva < exportRVA + exportSize)
			continue;
		/* Only exported code is meaningful for inline-hook checks. */
		if (!IsExecutableRva(localImage, imageSize, rva))
			continue;
		if (rva + PROLOGUE_SIZE > imageSize)
			continue;

		/* Read prologue from remote process */
		BYTE remoteBytes[PROLOGUE_SIZE]{};
		SIZE_T bytesRead = 0;
		ULONG_PTR funcAddr = (ULONG_PTR)hModule + rva;
		if (!ReadProcessMemory(hProcess, (LPCVOID)funcAddr, remoteBytes, PROLOGUE_SIZE, &bytesRead))
			continue;
		if (bytesRead < PROLOGUE_SIZE)
			continue;

		BYTE* diskBytes = localImage + rva;

		/* Compare prologues */
		if (memcmp(diskBytes, remoteBytes, PROLOGUE_SIZE) == 0)
			continue;

		/* Detect specific hook patterns */
		bool isHook = false;
		bool isPatchedPrologue = false;
		std::string hookDetail;
		ULONG_PTR hookTarget = 0;

		/* Pattern 1: E9 xx xx xx xx (JMP rel32) */
		if (remoteBytes[0] == 0xE9) {
			int32_t rel = *(int32_t*)(remoteBytes + 1);
			hookTarget = funcAddr + 5 + rel;
			isHook = true;
			hookDetail = "JMP rel32 (0xE9) at prologue";
		}
		/* Pattern 2: FF 25 xx xx xx xx (JMP [rip+disp32]) */
		else if (remoteBytes[0] == 0xFF && remoteBytes[1] == 0x25) {
			int32_t disp = *(int32_t*)(remoteBytes + 2);
			ULONG_PTR ptrAddr = funcAddr + 6 + disp;
			ReadProcessMemory(hProcess, (LPCVOID)ptrAddr, &hookTarget, sizeof(hookTarget), &bytesRead);
			isHook = true;
			hookDetail = "JMP [rip+disp32] (0xFF25) at prologue";
		}
		/* Pattern 3: 48 B8 xx...xx FF E0 (mov rax, imm64; jmp rax) */
		else if (remoteBytes[0] == 0x48 && remoteBytes[1] == 0xB8 &&
			remoteBytes[10] == 0xFF && remoteBytes[11] == 0xE0) {
			hookTarget = *(ULONG_PTR*)(remoteBytes + 2);
			isHook = true;
			hookDetail = "MOV RAX, imm64; JMP RAX at prologue";
		}
		/* Pattern 4: 68 xx xx xx xx C3 (PUSH imm32; RET — 32-bit trampoline) */
		else if (remoteBytes[0] == 0x68 && remoteBytes[5] == 0xC3) {
			hookTarget = *(uint32_t*)(remoteBytes + 1);
			isHook = true;
			hookDetail = "PUSH imm32; RET at prologue";
		}
		/* Generic: bytes differ, but there is no clear entry trampoline. */
		else if (memcmp(diskBytes, remoteBytes, 8) != 0) {
			isPatchedPrologue = true;
			hookDetail = "Prologue bytes modified (no direct jump pattern)";
			char hexDisk[48]{}, hexRemote[48]{};
			for (int b = 0; b < 8; b++) {
				sprintf_s(hexDisk + b * 3, sizeof(hexDisk) - b * 3, "%02X ", diskBytes[b]);
				sprintf_s(hexRemote + b * 3, sizeof(hexRemote) - b * 3, "%02X ", remoteBytes[b]);
			}
			hookDetail += " disk=[" + std::string(hexDisk, 23) + "] mem=[" + std::string(hexRemote, 23) + "]";
		}

		if (!isHook && !isPatchedPrologue)
			continue;

		/* Resolve function name */
		std::string funcName;
		if (diskNames && diskOrdinals) {
			for (DWORD n = 0; n < exportDir->NumberOfNames; n++) {
				if (diskOrdinals[n] == i) {
					DWORD nameRVA = diskNames[n];
					if (nameRVA < imageSize)
						funcName = (const char*)(localImage + nameRVA);
					break;
				}
			}
		}
		if (funcName.empty()) {
			char buf[32];
			sprintf_s(buf, "Ordinal#%u", i + exportDir->Base);
			funcName = buf;
		}

		std::string targetModule = hookTarget ? ResolveModuleForAddress(hProcess, hookTarget) : "";
		bool sameModuleRedirect = isHook && !targetModule.empty() && _stricmp(targetModule.c_str(), moduleName.c_str()) == 0;
		bool outsideModules = isHook && targetModule == "<outside all modules>";

		auto hook = std::make_shared<HookEntry>();
		hook->Type = isPatchedPrologue ? HookType::PatchedPrologue :
			(sameModuleRedirect ? HookType::InlineRedirect : HookType::Inline);
		hook->Module = moduleName;
		hook->Function = funcName;
		hook->OriginalAddress = funcAddr;
		hook->HookedAddress = hookTarget;
		hook->HookTarget = targetModule;
		if (sameModuleRedirect)
			hook->Details = hookDetail + " (same-module redirect)";
		else if (outsideModules)
			hook->Details = hookDetail + " (target outside loaded modules)";
		else
			hook->Details = hookDetail;
		hook->ByteCount = static_cast<unsigned int>(PROLOGUE_SIZE);
		memcpy(hook->Bytes, remoteBytes, PROLOGUE_SIZE);
		hook->Disassembly = DisassembleBytes(remoteBytes, static_cast<unsigned int>(PROLOGUE_SIZE), funcAddr);
		hook->Disassembly = AnnotateDisassemblyTarget(hook->Disassembly, hookTarget, targetModule);
		if (hook->Disassembly.empty())
			hook->Disassembly = "Unable to disassemble bytes\nbytes: " + FormatBytes(remoteBytes, static_cast<unsigned int>(PROLOGUE_SIZE));
		if (sameModuleRedirect) {
			// Same-module redirect — skip entirely, not a real hook
			continue;
		}
		else if (isPatchedPrologue) {
			// Patched prologue with no recognized jump — always suspicious
			hook->Suspicious = true;
		}
		else if (outsideModules) {
			// Target outside all loaded modules — always suspicious
			hook->Suspicious = true;
		}
		else {
			// Inline hook to another module — skip if target is Microsoft-signed
			bool targetSigned = IsTargetMicrosoftSigned(hProcess, targetModule, sigCache);
			if (targetSigned)
				continue;
			hook->Suspicious = true;
		}
		result.hooks.push_back(std::move(hook));
		result.suspiciousCount++;
	}
}

UserHooksView::ScanResult UserHooksView::ScanProcessAsync(DWORD pid) {
	ScanResult result{};

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (!hProcess) {
		result.status = "Failed to open process (access denied or invalid PID)";
		return result;
	}

	HMODULE modules[1024];
	DWORD cbNeeded = 0;
	if (!EnumProcessModulesEx(hProcess, modules, sizeof(modules), &cbNeeded, LIST_MODULES_ALL)) {
		result.status = "Failed to enumerate modules";
		CloseHandle(hProcess);
		return result;
	}

	DWORD moduleCount = cbNeeded / sizeof(HMODULE);
	SignatureCache sigCache;

	for (DWORD i = 0; i < moduleCount; i++) {
		char modName[MAX_PATH]{};
		if (!GetModuleBaseNameA(hProcess, modules[i], modName, MAX_PATH))
			continue;

		SIZE_T diskImageSize = 0;
		BYTE* diskImage = LoadDiskImage(hProcess, modules[i], diskImageSize);
		if (!diskImage) {
			continue;
		}

		ScanModuleIATStatic(hProcess, modules[i], modName, diskImage, diskImageSize, result, sigCache);
		ScanModuleEATStatic(hProcess, modules[i], modName, diskImage, diskImageSize, result, sigCache);
		ScanModuleInlineStatic(hProcess, modules[i], modName, diskImage, diskImageSize, result, sigCache);

		VirtualFree(diskImage, 0, MEM_RELEASE);
	}

	CloseHandle(hProcess);

	char buf[128];
	sprintf_s(buf, "Scanned %u modules in PID %u: %d hooks found", moduleCount, pid, result.suspiciousCount);
	result.status = buf;
	return result;
}

void UserHooksView::ScanProcess(DWORD pid) {
	_hooks.clear();
	_suspiciousCount = 0;
	_selectedHook = nullptr;
	_disasmHook = nullptr;
	_scanning = true;
	_scanned = false;
	_scanStatus = "Scanning...";

	LoggerView::AddLog(LoggerView::UserModeLog, "User Hooks: Starting scan of PID %u...", pid);

	_scanFuture = std::async(std::launch::async, [pid]() {
		return ScanProcessAsync(pid);
	});
}

void UserHooksView::RefreshNow() {
	if (_targetPid > 0 && !_scanning)
		ScanProcess(_targetPid);
}

bool UserHooksView::HasPendingAsync() const {
	return _scanning;
}

void UserHooksView::DoSort(int col, bool asc) {
	std::sort(_hooks.begin(), _hooks.end(), [=](const auto& a, const auto& b) {
		switch (col) {
		case 0: return SortHelper::SortStrings(a->Module, b->Module, asc);
		case 1: return SortHelper::SortStrings(a->Function, b->Function, asc);
		case 2: {
			int ta = (int)a->Type, tb = (int)b->Type;
			return SortHelper::SortNumbers(ta, tb, asc);
		}
		case 3: return SortHelper::SortNumbers(a->HookedAddress, b->HookedAddress, asc);
		case 4: return SortHelper::SortStrings(a->HookTarget, b->HookTarget, asc);
		case 5: return SortHelper::SortStrings(a->Details, b->Details, asc);
		}
		return false;
	});
}

void UserHooksView::BuildWindow() {
	// Poll async scan result
	if (_scanning && _scanFuture.valid() &&
		_scanFuture.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
		auto result = _scanFuture.get();
		_hooks = std::move(result.hooks);
		_suspiciousCount = result.suspiciousCount;
		_scanStatus = result.status;
		_scanning = false;
		_scanned = true;
		LoggerView::AddLog(LoggerView::UserModeLog, "User Hooks: %s", _scanStatus.c_str());
	}

	BuildToolBar();
	BuildTable();
	BuildDetailsPanel();
}

void UserHooksView::BuildToolBar() {
	Separator();
	Text("PID: %u", _targetPid);
	SameLine();

	if (_scanning) {
		BeginDisabled();
		Button("Scanning...");
		EndDisabled();
		SameLine();
		TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "Analysing PID %u (check log for progress)", _targetPid);
	}
	else {
		if (Button("Refresh")) {
			if (_targetPid > 0)
				ScanProcess(_targetPid);
			else
				_scanStatus = "No process selected";
		}
	}

	if (_scanned && !_scanning) {
		SameLine();
		if (_suspiciousCount > 0)
			TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "%d hooks detected!", _suspiciousCount);
		else
			TextColored(ImVec4(0.0f, 1.0f, 0.4f, 1.0f), "Clean - no hooks found");
	}

	if (!_scanStatus.empty() && !_scanning) {
		SameLine();
		TextDisabled("(%s)", _scanStatus.c_str());
	}

	Separator();
}

void UserHooksView::BuildTable() {
	if (!_scanned || _hooks.empty()) {
		if (_scanned && _hooks.empty())
			Text("No hooks detected in PID %u.", _targetPid);
		return;
	}

	float reservedDetailsHeight = _selectedHook ? 220.0f : 0.0f;
	float tableHeight = (std::max)(120.0f, GetContentRegionAvail().y - reservedDetailsHeight);

	if (BeginTable("userHooksTable", 6,
		ImGuiTableFlags_Sortable | ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable |
		ImGuiTableFlags_ScrollX | ImGuiTableFlags_ScrollY |
		ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders,
		ImVec2(0.0f, tableHeight))) {

		TableSetupScrollFreeze(1, 1);
		TableSetupColumn("Module", ImGuiTableColumnFlags_NoHide);
		TableSetupColumn("Function");
		TableSetupColumn("Type");
		TableSetupColumn("Hooked Address");
		TableSetupColumn("Hook Target");
		TableSetupColumn("Details");
		TableHeadersRow();

		auto specs = TableGetSortSpecs();
		if (specs && specs->SpecsDirty) {
			_specs = specs->Specs;
			DoSort(_specs->ColumnIndex, _specs->SortDirection == ImGuiSortDirection_Ascending);
			specs->SpecsDirty = false;
		}

		auto filter = GetFilterTextLower();
		ImGuiListClipper clipper;
		std::vector<int> indices;
		indices.reserve(_hooks.size());

		for (int i = 0; i < (int)_hooks.size(); i++) {
			if (!filter.IsEmpty()) {
				CString name(_hooks[i]->Function.c_str());
				name.MakeLower();
				CString mod(_hooks[i]->Module.c_str());
				mod.MakeLower();
				if (name.Find(filter) < 0 && mod.Find(filter) < 0)
					continue;
			}
			indices.push_back(i);
		}

		clipper.Begin((int)indices.size());
		while (clipper.Step()) {
			for (int j = clipper.DisplayStart; j < clipper.DisplayEnd; j++) {
				auto& h = _hooks[indices[j]];
				TableNextRow();

				ImVec4 textColor;
				switch (h->Type) {
				case HookType::Inline:
					textColor = ImVec4(1.0f, 0.2f, 0.2f, 1.0f);
					TableSetBgColor(ImGuiTableBgTarget_RowBg0, IM_COL32(180, 0, 0, 40));
					break;
				case HookType::InlineRedirect:
					textColor = ImVec4(0.95f, 0.75f, 0.2f, 1.0f);
					TableSetBgColor(ImGuiTableBgTarget_RowBg0, IM_COL32(180, 130, 0, 24));
					break;
				case HookType::PatchedPrologue:
					textColor = ImVec4(1.0f, 0.75f, 0.2f, 1.0f);
					TableSetBgColor(ImGuiTableBgTarget_RowBg0, IM_COL32(180, 120, 0, 28));
					break;
				case HookType::EAT:
					textColor = ImVec4(1.0f, 0.5f, 0.0f, 1.0f);
					TableSetBgColor(ImGuiTableBgTarget_RowBg0, IM_COL32(180, 100, 0, 40));
					break;
				case HookType::IAT:
					textColor = ImVec4(1.0f, 0.8f, 0.0f, 1.0f);
					break;
				}

				PushStyleColor(ImGuiCol_Text, textColor);

				TableSetColumnIndex(0);
				CStringA str;
				str.Format("%s##uh%d", h->Module.c_str(), indices[j]);
				Selectable(str, _selectedHook == h, ImGuiSelectableFlags_SpanAllColumns);
				if (IsItemClicked())
					_selectedHook = h;
				if (IsItemHovered() && IsMouseDoubleClicked(ImGuiMouseButton_Left) &&
					(h->Type == HookType::Inline || h->Type == HookType::PatchedPrologue)) {
					_selectedHook = h;
					_disasmHook = h;
					_showDisasmPopup = true;
				}
				if (BeginPopupContextItem()) {
					_selectedHook = h;
					if (MenuItem("Copy Function"))
						ImGui::SetClipboardText(h->Function.c_str());
					if (MenuItem("Copy Hook Address")) {
						char buf[32]{};
						sprintf_s(buf, "0x%016llX", h->HookedAddress);
						ImGui::SetClipboardText(buf);
					}
					if (MenuItem("Disassemble", nullptr, false,
						h->Type == HookType::Inline || h->Type == HookType::PatchedPrologue)) {
						_disasmHook = h;
						_showDisasmPopup = true;
					}
					EndPopup();
				}

				if (TableSetColumnIndex(1))
					Text("%s", h->Function.c_str());

				if (TableSetColumnIndex(2))
					Text("%s", HookTypeToString(h->Type));

				if (TableSetColumnIndex(3)) {
					if (h->HookedAddress)
						Text("0x%016llX", h->HookedAddress);
					else
						TextUnformatted("<unknown>");
				}

				if (TableSetColumnIndex(4))
					Text("%s", h->HookTarget.c_str());

				if (TableSetColumnIndex(5))
					Text("%s", h->Details.c_str());

				PopStyleColor();
			}
		}

		EndTable();
	}
}

void UserHooksView::BuildDetailsPanel() {
	if (_showDisasmPopup && _disasmHook) {
		OpenPopup("Hook Disassembly");
		_showDisasmPopup = false;
	}

	if (BeginPopupModal("Hook Disassembly", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
		if (_disasmHook) {
			Text("Module: %s", _disasmHook->Module.c_str());
			Text("Function: %s", _disasmHook->Function.c_str());
			if (_disasmHook->HookTarget.empty())
				Text("Hook Target: <unknown>");
			else
				Text("Hook Target: %s", _disasmHook->HookTarget.c_str());
			Separator();
			Text("Bytes: %s", FormatBytes(_disasmHook->Bytes, _disasmHook->ByteCount).c_str());
			Separator();
			TextUnformatted("Disassembly");
			BeginChild("##HookDisasmText", ImVec2(560, 120), true);
			TextUnformatted(_disasmHook->Disassembly.c_str());
			EndChild();
		}
		if (Button("Close"))
			CloseCurrentPopup();
		EndPopup();
	}

	if (!_selectedHook)
		return;

	auto& h = _selectedHook;

	Separator();
	Text("Hook Details: %s!%s", h->Module.c_str(), h->Function.c_str());
	Separator();

	BeginChild("##HookDetailsPanel", ImVec2(0.0f, 180.0f), false);
		if (BeginTable("hookDetails", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingFixedFit,
			ImVec2(0.0f, 0.0f))) {
		TableSetupColumn("Field", ImGuiTableColumnFlags_WidthFixed, 180.0f);
		TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);

		auto Row = [](const char* field, const char* fmt, ...) {
			TableNextRow();
			TableSetColumnIndex(0);
			TextUnformatted(field);
			TableSetColumnIndex(1);
			va_list args;
			va_start(args, fmt);
			TextV(fmt, args);
			va_end(args);
		};

		Row("Hook Type", "%s", HookTypeToString(h->Type));
		Row("Module", "%s", h->Module.c_str());
		Row("Function", "%s", h->Function.c_str());
		if (h->OriginalAddress)
			Row("Original Address", "0x%016llX", h->OriginalAddress);
		if (h->HookedAddress)
			Row("Hooked Address", "0x%016llX", h->HookedAddress);
		else
			Row("Hooked Address", "%s", "<unknown>");
		if (!h->HookTarget.empty())
			Row("Target Module", "%s", h->HookTarget.c_str());
		Row("Details", "%s", h->Details.c_str());

			EndTable();
		}
	EndChild();
}
