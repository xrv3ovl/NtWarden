#pragma once

#include <Windows.h>
#include <string>
#include <vector>

struct WindowsBuildInfo {
	DWORD Major{ 0 };
	DWORD Minor{ 0 };
	DWORD Build{ 0 };
	DWORD Ubr{ 0 };
	std::wstring DisplayVersion;
	std::wstring KernelImage;
	std::wstring VersionString() const;
};

struct StructureField {
	std::wstring Name;
	std::wstring TypeName;
	std::wstring Comment;
	ULONG Offset{ 0 };
	ULONG Size{ 0 };
	ULONG BitWidth{ 0 };
	std::vector<StructureField> Children;
};

struct StructureDefinition {
	std::wstring Name;
	std::wstring Category;
	std::wstring Source;
	ULONG Size{ 0 };
	std::vector<StructureField> Fields;
};
