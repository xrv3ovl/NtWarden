#include "pch.h"
#include "SymbolView.h"
#include "LoggerView.h"
#include "imgui.h"

#include <algorithm>
#include <Psapi.h>
#include "KernelModuleTracker.h"
#pragma comment(lib, "psapi.lib")

namespace {
	std::wstring ToLower(std::wstring text) {
		std::transform(text.begin(), text.end(), text.begin(), towlower);
		return text;
	}

	std::string WideToUtf8(const std::wstring& text) {
		if (text.empty())
			return {};
		auto length = ::WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
		if (length <= 0)
			return {};
		std::string utf8(length, '\0');
		::WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), utf8.data(), length, nullptr, nullptr);
		return utf8;
	}

	std::wstring Utf8ToWide(const std::string& text) {
		if (text.empty())
			return {};
		auto length = ::MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0);
		if (length <= 0)
			return {};
		std::wstring wide(length, L'\0');
		::MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), wide.data(), length);
		return wide;
	}

	bool IsTypeTag(SymbolTag tag) {
		return tag == SymbolTag::UDT || tag == SymbolTag::Enum || tag == SymbolTag::Typedef;
	}

	bool IsBrowsableTypeName(const std::wstring& name) {
		if (name.empty())
			return false;
		if (_wcsicmp(name.c_str(), L"<unnamed-tag>") == 0)
			return false;
		if (_wcsicmp(name.c_str(), L"<anonymous-tag>") == 0)
			return false;
		if (_wcsicmp(name.c_str(), L"<anonymous>") == 0)
			return false;
		return true;
	}

	std::wstring GetWindowsReleaseLabel(const WindowsBuildInfo& info) {
		if (!info.DisplayVersion.empty())
			return info.DisplayVersion;

		if (info.Major == 10 && info.Minor == 0) {
			switch (info.Build) {
			case 10240: return L"1507";
			case 10586: return L"1511";
			case 14393: return L"1607";
			case 15063: return L"1703";
			case 16299: return L"1709";
			case 17134: return L"1803";
			case 17763: return L"1809";
			case 18362: return L"1903";
			case 18363: return L"1909";
			case 19041: return L"2004";
			case 19042: return L"20H2";
			case 19043: return L"21H1";
			case 19044: return L"21H2";
			case 19045: return L"22H2";
			case 22000: return L"21H2";
			case 22621: return L"22H2";
			case 22631: return L"23H2";
			case 26100: return L"24H2";
			default:
				break;
			}
		}

		return L"";
	}
}

std::wstring WindowsBuildInfo::VersionString() const {
	wchar_t buffer[160]{};
	auto release = GetWindowsReleaseLabel(*this);
	if (Ubr != 0)
		swprintf_s(buffer, L"%lu.%lu.%lu.%lu", Major, Minor, Build, Ubr);
	else
		swprintf_s(buffer, L"%lu.%lu.%lu", Major, Minor, Build);
	if (!release.empty())
		return release + L" (build " + buffer + L")";
	return std::wstring(L"build ") + buffer;
}

SymbolView::SymbolView() {
	_buildInfo = WindowsVersionDetector::Detect();
	_symbolHelper = std::make_unique<SymbolHelper>();
}

void SymbolView::RefreshNow(SymbolScope scope) {
	RefreshModules(scope);
}

void SymbolView::RefreshModules(SymbolScope scope) {
	_activeScope = scope;
	_selectedModuleIndex = -1;
	_moduleSymbols.clear();
	_moduleTypes.clear();
	_typeMembers.clear();
	_selectedTypeName.clear();
	_selectedTypeSize = 0;

	_modules.clear();
	if (scope == SymbolScope::Kernel) {
	WinSys::KernelModuleTracker tracker;
	tracker.EnumModules();
	auto& modules = tracker.GetModules();

	_modules.reserve(modules.size());

	for (auto& km : modules) {
		LoadedModuleInfo info;
		info.Name = Utf8ToWide(km->Name);
		info.FullPath = Utf8ToWide(km->FullPath);
		info.BaseAddress = reinterpret_cast<DWORD64>(km->ImageBase);
		info.ImageSize = km->ImageSize;
		info.SymbolStatus = L"Not loaded";
		_modules.push_back(std::move(info));
	}
		LoggerView::AddLog(LoggerView::UserModeLog, "Enumerated %zu kernel modules", _modules.size());
	}
	else {
		HMODULE modules[1024]{};
		DWORD needed = 0;
		if (::EnumProcessModulesEx(::GetCurrentProcess(), modules, sizeof(modules), &needed, LIST_MODULES_ALL)) {
			auto count = static_cast<unsigned>(needed / sizeof(HMODULE));
			_modules.reserve(count);
			for (unsigned i = 0; i < count; i++) {
				wchar_t path[MAX_PATH]{};
				if (!::GetModuleFileNameExW(::GetCurrentProcess(), modules[i], path, _countof(path)))
					continue;

				MODULEINFO mi{};
				if (!::GetModuleInformation(::GetCurrentProcess(), modules[i], &mi, sizeof(mi)))
					continue;

				LoadedModuleInfo info;
				info.FullPath = path;
				const wchar_t* slash = wcsrchr(path, L'\\');
				info.Name = slash ? slash + 1 : path;
				info.BaseAddress = reinterpret_cast<DWORD64>(mi.lpBaseOfDll);
				info.ImageSize = mi.SizeOfImage;
				info.SymbolStatus = L"Not loaded";
				_modules.push_back(std::move(info));
			}
		}
		LoggerView::AddLog(LoggerView::UserModeLog, "Enumerated %zu user modules", _modules.size());
	}

	_modulesEnumerated = true;
}

void SymbolView::LoadSymbolsAsync(int moduleIndex) {
	if (moduleIndex < 0 || moduleIndex >= static_cast<int>(_modules.size()))
		return;

	auto& mod = _modules[moduleIndex];
	if (mod.SymbolsLoaded || mod.Loading)
		return;

	mod.Loading = true;
	mod.SymbolStatus = L"Loading...";

	std::thread([this, moduleIndex]() {
		auto& mod = _modules[moduleIndex];

		bool ok = _symbolHelper->LoadSymbolsForModule(mod);
		if (ok) {
			auto symbols = _symbolHelper->EnumerateSymbols(mod);
			auto types = _symbolHelper->EnumerateTypes(mod);
			std::lock_guard lock(_mutex);
			_moduleSymbols[moduleIndex] = std::move(symbols);
			_moduleTypes[moduleIndex] = std::move(types);
		}
	}).detach();
}

bool SymbolView::MatchesFilter(const std::wstring& name) const {
	if (_filter[0] == 0)
		return true;
	auto needle = ToLower(CStringW(_filter).GetString());
	return ToLower(name).find(needle) != std::wstring::npos;
}

void SymbolView::SelectType(const std::wstring& typeName) {
	if (_selectedModuleIndex < 0)
		return;

	_selectedTypeName = typeName;
	_memberFilter[0] = 0;
	auto& cache = _typeMembers[_selectedModuleIndex];
	if (cache.find(typeName) == cache.end()) {
		cache[typeName] = _symbolHelper->EnumerateTypeMembers(_modules[_selectedModuleIndex].BaseAddress, typeName.c_str());
	}
	_selectedTypeSize = _symbolHelper->GetStructSize(_modules[_selectedModuleIndex].BaseAddress, typeName.c_str());
}

void SymbolView::EnsureScope(SymbolScope scope) {
	if (_activeScope != scope || !_modulesEnumerated)
		RefreshModules(scope);
}

void SymbolView::BuildModulePane() {
	ImGui::BeginChild("##ModuleList", ImVec2(240, 0), true);
	ImGui::TextUnformatted(_activeScope == SymbolScope::Kernel ? "Kernel Modules" : "User Modules");
	ImGui::Separator();

	if (!_modulesEnumerated) {
		if (ImGui::Button("Enumerate Modules"))
			RefreshModules(_activeScope);
		ImGui::TextWrapped("Click to enumerate loaded modules for the active scope.");
		ImGui::EndChild();
		return;
	}

	ImGui::Text("%zu modules", _modules.size());
	ImGui::Separator();

	for (int i = 0; i < static_cast<int>(_modules.size()); i++) {
		auto& mod = _modules[i];
		auto name = WideToUtf8(mod.Name);

		bool selected = (i == _selectedModuleIndex);
		ImVec4 color;
		if (mod.SymbolsLoaded)
			color = ImVec4(0.4f, 0.9f, 0.4f, 1.0f);
		else if (mod.Loading)
			color = ImVec4(0.9f, 0.9f, 0.2f, 1.0f);
		else
			color = ImVec4(0.6f, 0.6f, 0.6f, 1.0f);

		ImGui::PushStyleColor(ImGuiCol_Text, color);
		if (ImGui::Selectable(name.c_str(), selected)) {
			_selectedModuleIndex = i;
			if (!mod.SymbolsLoaded && !mod.Loading)
				LoadSymbolsAsync(i);
		}
		ImGui::PopStyleColor();

		if (ImGui::IsItemHovered()) {
			ImGui::BeginTooltip();
			ImGui::Text("Path: %s", WideToUtf8(mod.FullPath).c_str());
			ImGui::Text("Base: 0x%llX", mod.BaseAddress);
			ImGui::Text("Size: 0x%X", mod.ImageSize);
			ImGui::Text("Status: %s", WideToUtf8(mod.SymbolStatus).c_str());
			ImGui::EndTooltip();
		}
	}

	ImGui::EndChild();
}

void SymbolView::BuildSymbolsTable(SymbolTag filterTag, bool typesOnly) {
	if (_selectedModuleIndex < 0) {
		ImGui::TextWrapped("Select a module to view its symbols.");
		return;
	}

	auto& mod = _modules[_selectedModuleIndex];
	if (mod.Loading) {
		ImGui::TextColored(ImVec4(0.9f, 0.9f, 0.2f, 1.0f), "Downloading PDB from symbol server...");
		return;
	}

	if (!mod.SymbolsLoaded) {
		ImGui::TextWrapped("Symbols not loaded.");
		if (ImGui::Button("Load Symbols"))
			LoadSymbolsAsync(_selectedModuleIndex);
		return;
	}

	std::lock_guard lock(_mutex);
	const auto& entriesMap = typesOnly ? _moduleTypes : _moduleSymbols;
	auto it = entriesMap.find(_selectedModuleIndex);
	if (it == entriesMap.end() || it->second.empty()) {
		ImGui::TextUnformatted(typesOnly ? "No type information found." : "No symbols found.");
		return;
	}

	auto& symbols = it->second;

	std::vector<int> filtered;
	filtered.reserve(symbols.size());
	for (int i = 0; i < static_cast<int>(symbols.size()); i++) {
		const auto& symbol = symbols[i];
		if (!MatchesFilter(symbol.Name))
			continue;
		if (typesOnly) {
			if (!IsTypeTag(symbol.Tag))
				continue;
			if (!IsBrowsableTypeName(symbol.Name))
				continue;
		}
		else if (filterTag != SymbolTag::Null && symbol.Tag != filterTag) {
			continue;
		}
		filtered.push_back(i);
	}

	ImGui::Text("%zu %s (%zu shown)", symbols.size(), typesOnly ? "types" : "symbols", filtered.size());

	if (ImGui::BeginTable("##SymbolsTable", 4,
		ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable |
		ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit)) {
		ImGui::TableSetupScrollFreeze(0, 1);
		ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_DefaultSort, 130);
		ImGui::TableSetupColumn("Size", 0, 70);
		ImGui::TableSetupColumn("Tag", 0, 100);
		ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
		ImGui::TableHeadersRow();

		ImGuiListClipper clipper;
		clipper.Begin(static_cast<int>(filtered.size()));
		while (clipper.Step()) {
			for (int j = clipper.DisplayStart; j < clipper.DisplayEnd; j++) {
				auto& sym = symbols[filtered[j]];
				auto name = WideToUtf8(sym.Name);
				auto tag = WideToUtf8(sym.TagName);

				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0);
				ImGui::Text("0x%llX", sym.Address);
				ImGui::TableSetColumnIndex(1);
				if (sym.Size > 0)
					ImGui::Text("0x%X", sym.Size);
				ImGui::TableSetColumnIndex(2);

				ImVec4 tagColor;
				switch (sym.Tag) {
				case SymbolTag::Function:    tagColor = ImVec4(0.4f, 0.7f, 1.0f, 1.0f); break;
				case SymbolTag::Data:        tagColor = ImVec4(0.9f, 0.7f, 0.3f, 1.0f); break;
				case SymbolTag::PublicSymbol: tagColor = ImVec4(0.6f, 0.6f, 0.6f, 1.0f); break;
				case SymbolTag::UDT:         tagColor = ImVec4(0.4f, 0.9f, 0.4f, 1.0f); break;
				case SymbolTag::Enum:        tagColor = ImVec4(0.8f, 0.5f, 0.9f, 1.0f); break;
				case SymbolTag::Typedef:     tagColor = ImVec4(0.5f, 0.8f, 0.8f, 1.0f); break;
				default:                     tagColor = ImVec4(0.5f, 0.5f, 0.5f, 1.0f); break;
				}
				ImGui::TextColored(tagColor, "%s", tag.c_str());

				ImGui::TableSetColumnIndex(3);
				if (typesOnly) {
					bool selectedType = _selectedTypeName == sym.Name;
					if (ImGui::Selectable(name.c_str(), selectedType, ImGuiSelectableFlags_SpanAllColumns))
						SelectType(sym.Name);
				}
				else {
					ImGui::TextUnformatted(name.c_str());
				}
			}
		}
		ImGui::EndTable();
	}
}

void SymbolView::BuildTypeBrowser() {
	if (_selectedTypeName.empty()) {
		ImGui::TextUnformatted("Select a type to inspect its structure.");
		return;
	}

	auto itModule = _typeMembers.find(_selectedModuleIndex);
	if (itModule == _typeMembers.end()) {
		ImGui::TextUnformatted("No type information loaded.");
		return;
	}
	auto itMembers = itModule->second.find(_selectedTypeName);
	if (itMembers == itModule->second.end()) {
		ImGui::TextUnformatted("No member information available.");
		return;
	}

	ImGui::Text("Type: %s", WideToUtf8(_selectedTypeName).c_str());
	if (_selectedTypeSize)
		ImGui::Text("Size: 0x%X", _selectedTypeSize);
	ImGui::InputTextWithHint("##MemberFilter", "Filter members (e.g. ActiveProcessLinks)", _memberFilter, _countof(_memberFilter));
	ImGui::Separator();

	std::vector<const TypeMemberEntry*> filteredMembers;
	filteredMembers.reserve(itMembers->second.size());
	auto memberNeedle = ToLower(CStringW(_memberFilter).GetString());
	for (const auto& member : itMembers->second) {
		if (_memberFilter[0]) {
			auto memberName = ToLower(member.Name);
			auto typeName = ToLower(member.TypeName);
			if (memberName.find(memberNeedle) == std::wstring::npos &&
				typeName.find(memberNeedle) == std::wstring::npos) {
				continue;
			}
		}
		filteredMembers.push_back(&member);
	}

	if (ImGui::BeginTable("##TypeMembers", 4,
		ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable |
		ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit)) {
		ImGui::TableSetupScrollFreeze(0, 1);
		ImGui::TableSetupColumn("Offset", 0, 90);
		ImGui::TableSetupColumn("Size", 0, 80);
		ImGui::TableSetupColumn("Field Type", 0, 180);
		ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
		ImGui::TableHeadersRow();

		for (const auto* member : filteredMembers) {
			ImGui::TableNextRow();
			ImGui::TableSetColumnIndex(0);
			ImGui::Text("0x%X", member->Offset);
			ImGui::TableSetColumnIndex(1);
			if (member->Size)
				ImGui::Text("0x%X", member->Size);
			ImGui::TableSetColumnIndex(2);
			ImGui::TextUnformatted(member->TypeName.empty() ? "?" : WideToUtf8(member->TypeName).c_str());
			ImGui::TableSetColumnIndex(3);
			ImGui::TextUnformatted(WideToUtf8(member->Name).c_str());
		}
		ImGui::EndTable();
	}
}

void SymbolView::BuildSymbolsPane() {
	if (ImGui::BeginTabBar("##SymbolCategoryTabs")) {
		if (ImGui::BeginTabItem("All")) {
			BuildSymbolsTable(SymbolTag::Null, false);
			ImGui::EndTabItem();
		}
		if (ImGui::BeginTabItem("Functions")) {
			BuildSymbolsTable(SymbolTag::Function, false);
			ImGui::EndTabItem();
		}
		if (ImGui::BeginTabItem("Publics")) {
			BuildSymbolsTable(SymbolTag::PublicSymbol, false);
			ImGui::EndTabItem();
		}
		if (ImGui::BeginTabItem("Types")) {
			auto avail = ImGui::GetContentRegionAvail();
			float minPaneHeight = 120.0f;
			float splitterHeight = 8.0f;
			float maxListHeight = (std::max)(minPaneHeight, avail.y - minPaneHeight - splitterHeight);
			_typeListHeight = (std::clamp)(_typeListHeight, minPaneHeight, maxListHeight);

			ImGui::BeginChild("##TypesList", ImVec2(0, _typeListHeight), false);
			BuildSymbolsTable(SymbolTag::Null, true);
			ImGui::EndChild();

			ImGui::InvisibleButton("##TypeSplitter", ImVec2(-1.0f, splitterHeight));
			if (ImGui::IsItemActive())
				_typeListHeight += ImGui::GetIO().MouseDelta.y;
			if (ImGui::IsItemHovered() || ImGui::IsItemActive())
				ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeNS);
			auto splitterMin = ImGui::GetItemRectMin();
			auto splitterMax = ImGui::GetItemRectMax();
			auto splitterColor = ImGui::GetColorU32(ImGui::IsItemActive() ? ImGuiCol_SeparatorActive :
				(ImGui::IsItemHovered() ? ImGuiCol_SeparatorHovered : ImGuiCol_Separator));
			ImGui::GetWindowDrawList()->AddRectFilled(splitterMin, splitterMax, splitterColor);

			ImGui::BeginChild("##TypeBrowser", ImVec2(0, 0), false);
			BuildTypeBrowser();
			ImGui::EndChild();
			ImGui::EndTabItem();
		}
		ImGui::EndTabBar();
	}
}

void SymbolView::BuildWindow(SymbolScope scope) {
	auto version = WideToUtf8(_buildInfo.VersionString());
	ImGui::Text("Windows Build: %s", version.c_str());
	if (_symbolHelper && _symbolHelper->IsInitialized()) {
		ImGui::SameLine();
		ImGui::TextDisabled("| Symbol Server: Connected");
	}

	EnsureScope(scope);
	ImGui::InputTextWithHint("##SymbolFilter", "Filter symbols", _filter, _countof(_filter));
	ImGui::Separator();
	BuildModulePane();
	ImGui::SameLine();
	ImGui::BeginChild("##Content", ImVec2(0, 0), false);
	BuildSymbolsPane();
	ImGui::EndChild();
}
