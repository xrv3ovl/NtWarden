#pragma once

#include "SymbolHelper.h"
#include "WindowsVersionDetector.h"

#include <memory>
#include <vector>
#include <unordered_map>
#include <thread>
#include <mutex>

enum class SymbolScope {
	Kernel,
	User,
};

class SymbolView {
public:
	SymbolView();
	void BuildWindow(SymbolScope scope);
	void RefreshNow(SymbolScope scope);

private:
	void RefreshModules(SymbolScope scope);
	void LoadSymbolsAsync(int moduleIndex);
	void BuildModulePane();
	void BuildSymbolsPane();
	void BuildSymbolsTable(SymbolTag filterTag, bool typesOnly);
	void BuildTypeBrowser();
	bool MatchesFilter(const std::wstring& name) const;
	void EnsureScope(SymbolScope scope);
	void SelectType(const std::wstring& typeName);

private:
	WindowsBuildInfo _buildInfo;
	std::unique_ptr<SymbolHelper> _symbolHelper;
	SymbolScope _activeScope{ SymbolScope::Kernel };

	std::vector<LoadedModuleInfo> _modules;
	int _selectedModuleIndex{ -1 };
	bool _modulesEnumerated{ false };

	std::unordered_map<int, std::vector<SymbolEntry>> _moduleSymbols;
	std::unordered_map<int, std::vector<SymbolEntry>> _moduleTypes;
	std::unordered_map<int, std::unordered_map<std::wstring, std::vector<TypeMemberEntry>>> _typeMembers;
	std::wstring _selectedTypeName;
	ULONG _selectedTypeSize{ 0 };
	float _typeListHeight{ 260.0f };
	char _filter[128]{};
	char _memberFilter[128]{};

	std::mutex _mutex;
};
