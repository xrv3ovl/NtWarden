#include "pch.h"
#include "RegistryView.h"

#include "LoggerView.h"
#include "RemoteClient.h"
#include "imgui_internal.h"

#include <algorithm>
#include <cwctype>
#include <filesystem>
#include <sstream>
#include <wincodec.h>

extern ID3D11Device* g_pd3dDevice;

namespace {
	BOOL WINAPI InitializeWicFactory(PINIT_ONCE, PVOID, PVOID* factory) noexcept {
#if (_WIN32_WINNT >= _WIN32_WINNT_WIN8) || defined(_WIN7_PLATFORM_UPDATE)
		auto hr = ::CoCreateInstance(
			CLSID_WICImagingFactory2,
			nullptr,
			CLSCTX_INPROC_SERVER,
			__uuidof(IWICImagingFactory2),
			factory);
		if (SUCCEEDED(hr))
			return TRUE;
#endif
		return SUCCEEDED(::CoCreateInstance(
			CLSID_WICImagingFactory1,
			nullptr,
			CLSCTX_INPROC_SERVER,
			__uuidof(IWICImagingFactory),
			factory)) ? TRUE : FALSE;
	}

	IWICImagingFactory* GetWic() noexcept {
		static INIT_ONCE once = INIT_ONCE_STATIC_INIT;
		IWICImagingFactory* factory = nullptr;
		if (!::InitOnceExecuteOnce(&once, InitializeWicFactory, nullptr, reinterpret_cast<LPVOID*>(&factory)))
			return nullptr;
		return factory;
	}

	std::wstring ResolveIconPath(std::wstring_view fileName) {
		WCHAR modulePath[MAX_PATH]{};
		::GetModuleFileName(nullptr, modulePath, _countof(modulePath));

		std::filesystem::path moduleDir(modulePath);
		moduleDir = moduleDir.parent_path();

		std::vector<std::filesystem::path> candidates{
			moduleDir / L"res" / fileName,
			moduleDir / L"..\\..\\NtWarden\\res" / fileName,
			std::filesystem::current_path() / L"NtWarden\\res" / fileName,
			std::filesystem::current_path() / L"res" / fileName,
		};

		for (const auto& candidate : candidates) {
			if (std::filesystem::exists(candidate))
				return candidate.wstring();
		}
		return {};
	}

	ID3D11ShaderResourceView* CreateTextureFromIconFile(std::wstring_view fileName) {
		auto path = ResolveIconPath(fileName);
		if (path.empty() || g_pd3dDevice == nullptr)
			return nullptr;

		auto* factory = GetWic();
		if (!factory)
			return nullptr;

		auto hIcon = static_cast<HICON>(::LoadImage(
			nullptr,
			path.c_str(),
			IMAGE_ICON,
			16,
			16,
			LR_LOADFROMFILE | LR_DEFAULTCOLOR));
		if (!hIcon)
			return nullptr;

		CComPtr<IWICBitmap> bitmap;
		auto hr = factory->CreateBitmapFromHICON(hIcon, &bitmap);
		::DestroyIcon(hIcon);
		if (FAILED(hr))
			return nullptr;

		UINT width = 0, height = 0;
		if (FAILED(bitmap->GetSize(&width, &height)) || width == 0 || height == 0)
			return nullptr;

		CComPtr<IWICBitmapLock> lock;
		if (FAILED(bitmap->Lock(nullptr, WICBitmapLockRead, &lock)))
			return nullptr;

		UINT bufferSize = 0;
		WICInProcPointer data = nullptr;
		if (FAILED(lock->GetDataPointer(&bufferSize, &data)) || data == nullptr)
			return nullptr;

		D3D11_TEXTURE2D_DESC desc{};
		desc.Width = width;
		desc.Height = height;
		desc.MipLevels = 1;
		desc.ArraySize = 1;
		desc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
		desc.SampleDesc.Count = 1;
		desc.Usage = D3D11_USAGE_DEFAULT;
		desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;

		D3D11_SUBRESOURCE_DATA initData{};
		initData.pSysMem = data;
		initData.SysMemPitch = width * 4;

		CComPtr<ID3D11Texture2D> texture;
		if (FAILED(g_pd3dDevice->CreateTexture2D(&desc, &initData, &texture)))
			return nullptr;

		D3D11_SHADER_RESOURCE_VIEW_DESC srvDesc{};
		srvDesc.Format = desc.Format;
		srvDesc.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D;
		srvDesc.Texture2D.MipLevels = 1;

		CComPtr<ID3D11ShaderResourceView> view;
		if (FAILED(g_pd3dDevice->CreateShaderResourceView(texture, &srvDesc, &view)))
			return nullptr;

		view.p->AddRef();
		return view.p;
	}

	class RegistryIconCache final {
	public:
		static RegistryIconCache& Get() {
			static RegistryIconCache cache;
			return cache;
		}

		ID3D11ShaderResourceView* GetTreeIcon(bool root) {
			return Load(root ? L"registry.ico" : L"directory.ico");
		}

		ID3D11ShaderResourceView* GetValueIcon(DWORD type, bool isDefault) {
			if (isDefault)
				return Load(L"link.ico");

			switch (type) {
			case REG_SZ:
			case REG_EXPAND_SZ:
			case REG_MULTI_SZ:
				return Load(L"message.ico");
			case REG_DWORD:
			case REG_QWORD:
				return Load(L"event-key.ico");
			case REG_BINARY:
				return Load(L"memory.ico");
			default:
				return Load(L"Object.ico");
			}
		}

	private:
		ID3D11ShaderResourceView* Load(std::wstring_view fileName) {
			auto key = std::wstring(fileName);
			if (auto it = _loaded.find(key); it != _loaded.end())
				return it->second;
			auto* view = CreateTextureFromIconFile(fileName);
			_loaded.insert({ key, view });
			return view;
		}

		std::unordered_map<std::wstring, ID3D11ShaderResourceView*> _loaded;
	};

	std::wstring ToLower(std::wstring_view text) {
		std::wstring lower(text.begin(), text.end());
		std::transform(lower.begin(), lower.end(), lower.begin(), [](wchar_t ch) {
			return static_cast<wchar_t>(std::towlower(ch));
		});
		return lower;
	}

	std::string WideToUtf8(std::wstring_view text) {
		if (text.empty())
			return {};
		auto length = ::WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
		std::string utf8(length, '\0');
		::WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), utf8.data(), length, nullptr, nullptr);
		return utf8;
	}

	std::wstring Utf8ToWide(std::string_view text) {
		if (text.empty())
			return {};
		auto length = ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
		std::wstring wide(length, L'\0');
		::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), wide.data(), length);
		return wide;
	}

	bool ContainsInsensitive(std::wstring_view value, const CString& filter) {
		if (filter.IsEmpty())
			return true;
		return ToLower(value).find(std::wstring(filter.GetString())) != std::wstring::npos;
	}

	const wchar_t* RegTypeToString(DWORD type) {
		switch (type) {
		case REG_SZ: return L"REG_SZ";
		case REG_EXPAND_SZ: return L"REG_EXPAND_SZ";
		case REG_BINARY: return L"REG_BINARY";
		case REG_DWORD: return L"REG_DWORD";
		case REG_MULTI_SZ: return L"REG_MULTI_SZ";
		case REG_QWORD: return L"REG_QWORD";
		default: return L"REG_UNKNOWN";
		}
	}

	DWORD RegTypeFromName(std::wstring_view typeName) {
		if (typeName == L"REG_SZ") return REG_SZ;
		if (typeName == L"REG_EXPAND_SZ") return REG_EXPAND_SZ;
		if (typeName == L"REG_BINARY") return REG_BINARY;
		if (typeName == L"REG_DWORD") return REG_DWORD;
		if (typeName == L"REG_MULTI_SZ") return REG_MULTI_SZ;
		if (typeName == L"REG_QWORD") return REG_QWORD;
		return 0;
	}

	bool IsEditableType(DWORD type) {
		switch (type) {
		case REG_SZ:
		case REG_EXPAND_SZ:
		case REG_DWORD:
		case REG_QWORD:
		case REG_BINARY:
			return true;
		default:
			return false;
		}
	}

	bool ParseHexBytes(std::string_view text, std::vector<BYTE>& out) {
		out.clear();
		size_t i = 0;
		while (i < text.size()) {
			if (text[i] == ' ' || text[i] == '\t' || text[i] == '\n' || text[i] == '\r') {
				i++;
				continue;
			}
			if (i + 1 >= text.size())
				return false;
			char hi = text[i], lo = text[i + 1];
			auto hexVal = [](char c) -> int {
				if (c >= '0' && c <= '9') return c - '0';
				if (c >= 'A' && c <= 'F') return c - 'A' + 10;
				if (c >= 'a' && c <= 'f') return c - 'a' + 10;
				return -1;
			};
			int h = hexVal(hi), l = hexVal(lo);
			if (h < 0 || l < 0)
				return false;
			out.push_back(static_cast<BYTE>((h << 4) | l));
			i += 2;
		}
		return true;
	}

	bool ParseUnsigned(std::string_view text, ULONGLONG& value) {
		auto start = text.find_first_not_of(" \t");
		if (start == std::string_view::npos)
			return false;
		auto end = text.find_last_not_of(" \t");
		text = text.substr(start, end - start + 1);
		int base = 10;
		if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
			base = 16;
			text.remove_prefix(2);
		}
		auto buffer = std::string(text);
		char* endPtr = nullptr;
		auto parsed = _strtoui64(buffer.c_str(), &endPtr, base);
		if (endPtr == nullptr || *endPtr != '\0')
			return false;
		value = parsed;
		return true;
	}

	std::wstring BytesToHex(const BYTE* data, DWORD size, DWORD maxBytes = 32) {
		std::wostringstream out;
		auto count = (std::min)(size, maxBytes);
		for (DWORD i = 0; i < count; i++) {
			if (i)
				out << L' ';
			out << std::hex << std::uppercase;
			out.width(2);
			out.fill(L'0');
			out << static_cast<unsigned>(data[i]);
		}
		if (size > maxBytes)
			out << L" ...";
		return out.str();
	}

	std::wstring MultiSzToText(const wchar_t* text, size_t chars) {
		std::wstring result;
		size_t index = 0;
		while (index < chars && text[index] != L'\0') {
			auto* current = text + index;
			size_t len = wcslen(current);
			if (!result.empty())
				result += L" | ";
			result.append(current, len);
			index += len + 1;
		}
		return result;
	}

	std::wstring RegDataToString(DWORD type, const BYTE* data, DWORD size) {
		if (data == nullptr || size == 0)
			return {};

		switch (type) {
		case REG_SZ:
		case REG_EXPAND_SZ:
			return std::wstring(reinterpret_cast<const wchar_t*>(data));

		case REG_MULTI_SZ:
			return MultiSzToText(reinterpret_cast<const wchar_t*>(data), size / sizeof(wchar_t));

		case REG_DWORD:
			if (size >= sizeof(DWORD)) {
				auto value = *reinterpret_cast<const DWORD*>(data);
				wchar_t buffer[64];
				swprintf_s(buffer, L"0x%08X (%u)", value, value);
				return buffer;
			}
			break;

		case REG_QWORD:
			if (size >= sizeof(ULONGLONG)) {
				auto value = *reinterpret_cast<const ULONGLONG*>(data);
				wchar_t buffer[64];
				swprintf_s(buffer, L"0x%016llX (%llu)", value, value);
				return buffer;
			}
			break;
		}

		return BytesToHex(data, size);
	}

	std::wstring RegDataToEditString(DWORD type, const BYTE* data, DWORD size) {
		if (data == nullptr || size == 0)
			return {};

		switch (type) {
		case REG_SZ:
		case REG_EXPAND_SZ:
			return std::wstring(reinterpret_cast<const wchar_t*>(data));

		case REG_DWORD:
			if (size >= sizeof(DWORD))
				return std::to_wstring(*reinterpret_cast<const DWORD*>(data));
			break;

		case REG_QWORD:
			if (size >= sizeof(ULONGLONG))
				return std::to_wstring(*reinterpret_cast<const ULONGLONG*>(data));
			break;

		case REG_BINARY:
			return BytesToHex(data, size, size);
		}

		return {};
	}

	bool StartsWithInsensitive(std::wstring_view value, std::wstring_view prefix) {
		if (value.size() < prefix.size())
			return false;
		return _wcsnicmp(std::wstring(value).c_str(), std::wstring(prefix).c_str(), static_cast<int>(prefix.size())) == 0;
	}
}

RegistryView::RegistryView() : ViewBase(0) {
}

void RegistryView::Refresh() {
	if (RemoteClient::IsConnected()) {
		_roots = CreateHiveRoots();
		if (!_roots.empty()) {
			if (_selectedNode == nullptr)
				SelectNode(_roots.front().get());
			else {
				for (auto& root : _roots) {
					if (root->FullPath == _selectedNode->FullPath) {
						SelectNode(root.get());
						break;
					}
				}
			}
		}
		_selectedValueIndex = -1;
		_editingValueIndex = -1;
		_openEditPopup = false;
		_keyWritable = false;
		*_editBuffer = '\0';
		*_editStatus = '\0';
		LoggerView::AddLog(LoggerView::UserModeLog, "Remote registry browser refreshed");
		return;
	}

	_roots = CreateHiveRoots();
	if (!_roots.empty()) {
		if (_selectedNode == nullptr)
			SelectNode(_roots.front().get());
		else {
			for (auto& root : _roots) {
				if (root->FullPath == _selectedNode->FullPath) {
					SelectNode(root.get());
					break;
				}
			}
		}
	}
	_selectedValueIndex = -1;
	_editingValueIndex = -1;
	_openEditPopup = false;
	_keyWritable = false;
	*_editBuffer = '\0';
	*_editStatus = '\0';
	LoggerView::AddLog(LoggerView::UserModeLog, "Registry browser refreshed");
}

void RegistryView::BuildWindow() {
	if (_roots.empty()) {
		Refresh();
	}
	BuildToolBar();
	BuildContent();
}

void RegistryView::BuildToolBar() {
	ImGui::Separator();
	DrawFilterToolbar();
}

void RegistryView::BuildContent() {
	auto avail = ImGui::GetContentRegionAvail();
	_treePaneWidth = (std::clamp)(_treePaneWidth, 220.0f, (std::max)(220.0f, avail.x - 280.0f));

	ImGui::BeginChild("##RegistryTree", ImVec2(_treePaneWidth, 0), true);
	BuildTreePane();
	ImGui::EndChild();

	ImGui::SameLine();
	ImGui::InvisibleButton("##RegistrySplitter", ImVec2(8.0f, avail.y));
	if (ImGui::IsItemActive())
		_treePaneWidth += ImGui::GetIO().MouseDelta.x;
	if (ImGui::IsItemHovered() || ImGui::IsItemActive())
		ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeEW);
	auto splitterColor = ImGui::GetColorU32(ImGui::IsItemActive() ? ImGuiCol_SeparatorActive :
		(ImGui::IsItemHovered() ? ImGuiCol_SeparatorHovered : ImGuiCol_Separator));
	ImGui::GetWindowDrawList()->AddRectFilled(ImGui::GetItemRectMin(), ImGui::GetItemRectMax(), splitterColor);

	ImGui::SameLine();
	ImGui::BeginChild("##RegistryValues", ImVec2(0, 0), false);
	BuildValuesPane();
	ImGui::EndChild();

	// Edit modal rendered at top level so it's always accessible
	if (_openEditPopup) {
		ImGui::OpenPopup("Edit Registry Value");
		_openEditPopup = false;
	}

	auto canEdit = _editingValueIndex >= 0 && _editingValueIndex < static_cast<int>(_values.size());
	if (ImGui::BeginPopupModal("Edit Registry Value", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
		if (!canEdit) {
			ImGui::TextDisabled("No editable value selected.");
		}
		else {
			const auto& editValue = _values[_editingValueIndex];
			ImGui::Text("Key: %s", WideToUtf8(_selectedNode ? _selectedNode->FullPath : L"").c_str());
			ImGui::Text("Value: %s", WideToUtf8(editValue.Name).c_str());
			ImGui::Text("Type: %s", WideToUtf8(editValue.TypeName).c_str());
			ImGui::Separator();

			if (editValue.Type == REG_DWORD)
				ImGui::InputTextWithHint("##RegistryEdit", "Decimal or 0x hex DWORD", _editBuffer, _countof(_editBuffer));
			else if (editValue.Type == REG_QWORD)
				ImGui::InputTextWithHint("##RegistryEdit", "Decimal or 0x hex QWORD", _editBuffer, _countof(_editBuffer));
			else if (editValue.Type == REG_BINARY) {
				ImGui::TextDisabled("Hex bytes separated by spaces (e.g. 0A 1B 2C)");
				ImGui::InputTextMultiline("##RegistryEdit", _editBuffer, _countof(_editBuffer), ImVec2(520.0f, ImGui::GetTextLineHeight() * 8.0f));
			}
			else
				ImGui::InputTextMultiline("##RegistryEdit", _editBuffer, _countof(_editBuffer), ImVec2(520.0f, ImGui::GetTextLineHeight() * 8.0f));

			if (*_editStatus != '\0')
				ImGui::TextWrapped("%s", _editStatus);

			if (ImGui::Button("Save")) {
				_selectedValueIndex = _editingValueIndex;
				if (SaveSelectedValue()) {
					auto editedName = editValue.Name;
					EnumerateValues();
					for (int i = 0; i < static_cast<int>(_values.size()); i++) {
						if (_values[i].Name == editedName) {
							_selectedValueIndex = i;
							_editingValueIndex = i;
							break;
						}
					}
					SyncEditorFromSelection();
					ImGui::CloseCurrentPopup();
				}
			}
			ImGui::SameLine();
			if (ImGui::Button("Cancel")) {
				SyncEditorFromSelection();
				ImGui::CloseCurrentPopup();
			}
		}
		ImGui::EndPopup();
	}
}

void RegistryView::BuildTreePane() {
	ImGui::TextUnformatted("Registry Hives");
	ImGui::Separator();
	for (auto& root : _roots)
		BuildNode(*root);
}

void RegistryView::BuildNode(RegistryNode& node) {
	ImGuiTreeNodeFlags flags = ImGuiTreeNodeFlags_OpenOnArrow | ImGuiTreeNodeFlags_OpenOnDoubleClick | ImGuiTreeNodeFlags_SpanAvailWidth;
	if (&node == _selectedNode)
		flags |= ImGuiTreeNodeFlags_Selected;
	if (node.Children.empty() && node.Enumerated)
		flags |= ImGuiTreeNodeFlags_Leaf;

	std::string label(node.Name.begin(), node.Name.end());
	auto open = ImGui::TreeNodeEx(static_cast<void*>(&node), flags, "%s", label.c_str());
	auto root = node.SubKeyPath.empty();
	auto icon = RegistryIconCache::Get().GetTreeIcon(root);
	if (icon) {
		auto min = ImGui::GetItemRectMin();
		auto y = min.y + (ImGui::GetTextLineHeight() - 16.0f) * 0.5f;
		ImGui::GetWindowDrawList()->AddImage(icon, ImVec2(min.x + 2.0f, y), ImVec2(min.x + 18.0f, y + 16.0f));
	}
	if (ImGui::IsItemClicked())
		SelectNode(&node);

	if (open) {
		EnsureChildrenEnumerated(node);
		for (auto& child : node.Children)
			BuildNode(*child);
		ImGui::TreePop();
	}
}

void RegistryView::BuildValuesPane() {
	// Sync path buffer when node selection changes (not while user is editing)
	if (_pathBufferDirty) {
		std::string path = _selectedNode ? WideToUtf8(_selectedNode->FullPath) : "";
		strcpy_s(_pathBuffer, path.c_str());
		_pathBufferDirty = false;
	}

	ImGui::Text("Key:");
	ImGui::SameLine();
	ImGui::PushItemWidth(-1);
	if (ImGui::InputText("##KeyPath", _pathBuffer, sizeof(_pathBuffer), ImGuiInputTextFlags_EnterReturnsTrue)) {
		auto wide = Utf8ToWide(std::string_view(_pathBuffer));
		NavigateToPath(wide);
	}
	ImGui::PopItemWidth();
	if (_selectedNode) {
		ImGui::TextDisabled("Values: %zu | %s", _values.size(), GetAccessStatusText().c_str());
		auto effective = GetEffectivePath();
		if (!effective.empty() && effective != _selectedNode->FullPath) {
			ImGui::TextDisabled("Effective Path: %s", WideToUtf8(effective).c_str());
		}
	}
	else {
		ImGui::TextDisabled("Values: %zu", _values.size());
	}
	ImGui::Separator();

	auto filter = GetFilterTextLower();
	if (ImGui::BeginTable("##RegistryValueTable", 3,
		ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
		ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable |
		ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_NoSavedSettings)) {
		ImGui::TableSetupScrollFreeze(1, 1);
		ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch, 1.35f);
		ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 120.0f);
		ImGui::TableSetupColumn("Data", ImGuiTableColumnFlags_WidthStretch, 2.4f);
		ImGui::TableHeadersRow();

		for (const auto& value : _values) {
			if (!ContainsInsensitive(value.Name, filter) &&
				!ContainsInsensitive(value.TypeName, filter) &&
				!ContainsInsensitive(value.DataText, filter))
				continue;

			std::string name(value.Name.begin(), value.Name.end());
			std::string type(value.TypeName.begin(), value.TypeName.end());
			std::string data(value.DataText.begin(), value.DataText.end());
			std::string id = name + "##" + type + data;
			int index = static_cast<int>(&value - _values.data());

			ImGui::TableNextRow();
			ImGui::TableSetColumnIndex(0);
			if (auto* icon = RegistryIconCache::Get().GetValueIcon(value.Type, value.IsDefault)) {
				ImGui::Image(icon, ImVec2(16, 16));
				ImGui::SameLine();
			}
			if (ImGui::Selectable(id.c_str(), _selectedValueIndex == index, ImGuiSelectableFlags_SpanAllColumns))
				SelectValue(index);
			bool editable = _keyWritable && IsEditableType(value.Type);
			if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && editable)
				OpenEditDialog(index);
			if (ImGui::BeginPopupContextItem()) {
				if (ImGui::MenuItem("Copy Name"))
					ImGui::SetClipboardText(name.c_str());
				if (ImGui::MenuItem("Copy Data"))
					ImGui::SetClipboardText(data.c_str());
				ImGui::Separator();
				if (ImGui::MenuItem("Edit", nullptr, false, editable))
					OpenEditDialog(index);
				ImGui::EndPopup();
			}
			ImGui::TableSetColumnIndex(1);
			ImGui::TextUnformatted(type.c_str());
			ImGui::TableSetColumnIndex(2);
			ImGui::TextUnformatted(data.c_str());
		}

		ImGui::EndTable();
	}
}


void RegistryView::EnsureChildrenEnumerated(RegistryNode& node) {
	if (node.Enumerated)
		return;

	if (RemoteClient::IsConnected()) {
		auto children = RemoteClient::EnumRegistrySubKeys(node.FullPath);
		node.Children.clear();
		node.Children.reserve(children.size());
		for (const auto& remoteChild : children) {
			auto name = Utf8ToWide(remoteChild.Name);
			auto child = std::make_unique<RegistryNode>();
			child->Name = name;
			child->RootKey = nullptr;
			child->SubKeyPath = node.SubKeyPath.empty() ? child->Name : node.SubKeyPath + L"\\" + child->Name;
			child->FullPath = node.FullPath + L"\\" + child->Name;
			node.Children.push_back(std::move(child));
		}
		std::sort(node.Children.begin(), node.Children.end(), [](const auto& left, const auto& right) {
			return _wcsicmp(left->Name.c_str(), right->Name.c_str()) < 0;
		});
		node.Enumerated = true;
		return;
	}

	wil::unique_hkey key;
	if (::RegOpenKeyExW(node.RootKey, node.SubKeyPath.empty() ? nullptr : node.SubKeyPath.c_str(), 0, KEY_READ, key.addressof()) != ERROR_SUCCESS) {
		node.Enumerated = true;
		return;
	}

	DWORD subKeyCount = 0;
	DWORD maxSubKeyLen = 0;
	if (::RegQueryInfoKeyW(key.get(), nullptr, nullptr, nullptr, &subKeyCount, &maxSubKeyLen, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
		node.Enumerated = true;
		return;
	}

	std::vector<wchar_t> name(maxSubKeyLen + 1);
	for (DWORD index = 0; index < subKeyCount; index++) {
		DWORD chars = static_cast<DWORD>(name.size());
		if (::RegEnumKeyExW(key.get(), index, name.data(), &chars, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
			continue;

		auto child = std::make_unique<RegistryNode>();
		child->Name.assign(name.data(), chars);
		child->RootKey = node.RootKey;
		child->SubKeyPath = node.SubKeyPath.empty() ? child->Name : node.SubKeyPath + L"\\" + child->Name;
		child->FullPath = node.FullPath + L"\\" + child->Name;
		node.Children.push_back(std::move(child));
	}

	std::sort(node.Children.begin(), node.Children.end(), [](const auto& left, const auto& right) {
		return _wcsicmp(left->Name.c_str(), right->Name.c_str()) < 0;
	});
	node.Enumerated = true;
}

void RegistryView::SelectNode(RegistryNode* node) {
	_selectedNode = node;
	_pathBufferDirty = true;
	_keyWritable = ProbeWriteAccess();
	EnumerateValues();
	_selectedValueIndex = _values.empty() ? -1 : 0;
	SyncEditorFromSelection();
}

void RegistryView::NavigateToPath(const std::wstring& path) {
	if (path.empty() || _roots.empty())
		return;

	// Split path into components by backslash
	std::vector<std::wstring> parts;
	size_t start = 0;
	while (start < path.size()) {
		auto pos = path.find(L'\\', start);
		if (pos == std::wstring::npos) {
			parts.push_back(path.substr(start));
			break;
		}
		parts.push_back(path.substr(start, pos - start));
		start = pos + 1;
	}
	if (parts.empty())
		return;

	// Find matching root hive (case-insensitive)
	RegistryNode* current = nullptr;
	for (auto& root : _roots) {
		if (_wcsicmp(root->Name.c_str(), parts[0].c_str()) == 0) {
			current = root.get();
			break;
		}
	}
	if (!current) {
		LoggerView::AddLog(LoggerView::UserModeLog, "Unknown registry hive: %ws", parts[0].c_str());
		return;
	}

	// Walk down the tree, expanding nodes as needed
	for (size_t i = 1; i < parts.size(); i++) {
		EnsureChildrenEnumerated(*current);
		RegistryNode* found = nullptr;
		for (auto& child : current->Children) {
			if (_wcsicmp(child->Name.c_str(), parts[i].c_str()) == 0) {
				found = child.get();
				break;
			}
		}
		if (!found) {
			LoggerView::AddLog(LoggerView::UserModeLog, "Registry subkey not found: %ws", parts[i].c_str());
			// Select as far as we got
			SelectNode(current);
			return;
		}
		current = found;
	}

	SelectNode(current);
}

void RegistryView::SelectValue(int index) {
	if (index < 0 || index >= static_cast<int>(_values.size()))
		return;
	_selectedValueIndex = index;
	SyncEditorFromSelection();
}

void RegistryView::OpenEditDialog(int index) {
	if (index < 0 || index >= static_cast<int>(_values.size()))
		return;
	_selectedValueIndex = index;
	_editingValueIndex = index;
	SyncEditorFromSelection();
	_openEditPopup = true;
}

void RegistryView::EnumerateValues() {
	_values.clear();
	if (_selectedNode == nullptr)
		return;

	if (RemoteClient::IsConnected()) {
		auto remoteValues = RemoteClient::EnumRegistryValues(_selectedNode->FullPath);
		_values.reserve(remoteValues.size());
		for (const auto& remoteValue : remoteValues) {
			RegistryValue value;
			value.IsDefault = remoteValue.IsDefault != 0;
			value.Name = Utf8ToWide(remoteValue.Name);
			value.Type = remoteValue.Type;
			value.TypeName = RegTypeToString(remoteValue.Type);
			value.DataText = RegDataToString(remoteValue.Type, remoteValue.Data, remoteValue.DataSize);
			value.EditText = RegDataToEditString(remoteValue.Type, remoteValue.Data, remoteValue.DataSize);
			_values.push_back(std::move(value));
		}
		return;
	}

	wil::unique_hkey key;
	if (::RegOpenKeyExW(_selectedNode->RootKey, _selectedNode->SubKeyPath.empty() ? nullptr : _selectedNode->SubKeyPath.c_str(), 0, KEY_READ, key.addressof()) != ERROR_SUCCESS)
		return;

	DWORD valueCount = 0;
	DWORD maxValueNameLen = 0;
	DWORD maxValueDataLen = 0;
	if (::RegQueryInfoKeyW(key.get(), nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
		&valueCount, &maxValueNameLen, &maxValueDataLen, nullptr, nullptr) != ERROR_SUCCESS)
		return;

	std::vector<wchar_t> valueName(maxValueNameLen + 2);
	std::vector<BYTE> data(maxValueDataLen + sizeof(wchar_t) * 2);
	for (DWORD index = 0; index < valueCount; index++) {
		DWORD nameChars = static_cast<DWORD>(valueName.size());
		DWORD dataBytes = static_cast<DWORD>(data.size());
		DWORD type = 0;
		if (::RegEnumValueW(key.get(), index, valueName.data(), &nameChars, nullptr, &type, data.data(), &dataBytes) != ERROR_SUCCESS)
			continue;

		RegistryValue value;
		value.IsDefault = nameChars == 0;
		value.Name = value.IsDefault ? L"(Default)" : std::wstring(valueName.data(), nameChars);
		value.Type = type;
		value.TypeName = RegTypeToString(type);
		value.DataText = RegDataToString(type, data.data(), dataBytes);
		value.EditText = RegDataToEditString(type, data.data(), dataBytes);
		_values.push_back(std::move(value));
	}
}

bool RegistryView::ProbeWriteAccess() const {
	if (RemoteClient::IsConnected())
		return false;

	if (_selectedNode == nullptr)
		return false;

	wil::unique_hkey key;
	auto status = ::RegOpenKeyExW(
		_selectedNode->RootKey,
		_selectedNode->SubKeyPath.empty() ? nullptr : _selectedNode->SubKeyPath.c_str(),
		0,
		KEY_SET_VALUE,
		key.addressof());
	return status == ERROR_SUCCESS;
}

std::wstring RegistryView::GetEffectivePath() const {
	if (_selectedNode == nullptr)
		return {};
	if (RemoteClient::IsConnected())
		return _selectedNode->FullPath;
	if (_selectedNode->RootKey != HKEY_CLASSES_ROOT)
		return _selectedNode->FullPath;

	wil::unique_hkey key;
	auto hkcuPath = std::wstring(L"Software\\Classes");
	if (!_selectedNode->SubKeyPath.empty())
		hkcuPath += L"\\" + _selectedNode->SubKeyPath;
	if (::RegOpenKeyExW(HKEY_CURRENT_USER, hkcuPath.c_str(), 0, KEY_READ, key.addressof()) == ERROR_SUCCESS)
		return L"HKEY_CURRENT_USER\\" + hkcuPath;

	auto hklmPath = std::wstring(L"Software\\Classes");
	if (!_selectedNode->SubKeyPath.empty())
		hklmPath += L"\\" + _selectedNode->SubKeyPath;
	return L"HKEY_LOCAL_MACHINE\\" + hklmPath;
}

std::string RegistryView::GetAccessStatusText() const {
	if (_selectedNode == nullptr)
		return "No key selected";
	if (RemoteClient::IsConnected())
		return "Remote (read-only)";
	if (_keyWritable)
		return "Writable";
	if (_selectedNode->RootKey == HKEY_CLASSES_ROOT)
		return "Read-only: HKCR often requires elevation or maps to HKLM";
	if (StartsWithInsensitive(_selectedNode->FullPath, L"HKEY_LOCAL_MACHINE"))
		return "Read-only: likely requires elevation";
	return "Read-only";
}

void RegistryView::SyncEditorFromSelection() {
	*_editBuffer = '\0';
	*_editStatus = '\0';
	if (_selectedValueIndex < 0 || _selectedValueIndex >= static_cast<int>(_values.size()))
		return;

	auto text = WideToUtf8(_values[_selectedValueIndex].EditText);
	strcpy_s(_editBuffer, text.c_str());
}

bool RegistryView::SaveSelectedValue() {
	if (RemoteClient::IsConnected()) {
		strcpy_s(_editStatus, "Remote registry editing is not implemented.");
		return false;
	}

	if (_selectedNode == nullptr || _selectedValueIndex < 0 || _selectedValueIndex >= static_cast<int>(_values.size())) {
		strcpy_s(_editStatus, "No value selected.");
		return false;
	}

	auto& value = _values[_selectedValueIndex];
	auto type = value.Type;
	if (!_keyWritable) {
		strcpy_s(_editStatus, "Access denied: key is not writable.");
		LoggerView::AddLog(LoggerView::UserModeLog, "Registry edit blocked for %ws: key is not writable", _selectedNode->FullPath.c_str());
		return false;
	}
	if (!IsEditableType(type)) {
		strcpy_s(_editStatus, "Editing for this type is not implemented.");
		LoggerView::AddLog(LoggerView::UserModeLog, "Registry edit blocked for %ws\\%ws: unsupported type %ws",
			_selectedNode->FullPath.c_str(),
			value.IsDefault ? L"(Default)" : value.Name.c_str(),
			value.TypeName.c_str());
		return false;
	}

	wil::unique_hkey key;
	if (::RegOpenKeyExW(
		_selectedNode->RootKey,
		_selectedNode->SubKeyPath.empty() ? nullptr : _selectedNode->SubKeyPath.c_str(),
		0,
		KEY_SET_VALUE,
		key.addressof()) != ERROR_SUCCESS) {
		strcpy_s(_editStatus, "Failed to open key for writing.");
		LoggerView::AddLog(LoggerView::UserModeLog, "Registry edit failed to open key for writing: %ws", _selectedNode->FullPath.c_str());
		return false;
	}

	auto valueName = value.IsDefault ? std::wstring() : value.Name;
	auto text = std::string_view(_editBuffer);
	LSTATUS status = ERROR_INVALID_DATA;

	if (type == REG_SZ || type == REG_EXPAND_SZ) {
		auto wide = Utf8ToWide(text);
		status = ::RegSetValueExW(
			key.get(),
			valueName.empty() ? nullptr : valueName.c_str(),
			0,
			type,
			reinterpret_cast<const BYTE*>(wide.c_str()),
			static_cast<DWORD>((wide.size() + 1) * sizeof(wchar_t)));
	}
	else if (type == REG_DWORD) {
		ULONGLONG parsed = 0;
		if (!ParseUnsigned(text, parsed) || parsed > 0xFFFFFFFFull) {
			strcpy_s(_editStatus, "Invalid DWORD. Use decimal or 0x-prefixed hex.");
			LoggerView::AddLog(LoggerView::UserModeLog, "Registry edit rejected invalid DWORD for %ws\\%ws",
				_selectedNode->FullPath.c_str(),
				value.IsDefault ? L"(Default)" : value.Name.c_str());
			return false;
		}
		auto data = static_cast<DWORD>(parsed);
		status = ::RegSetValueExW(
			key.get(),
			valueName.empty() ? nullptr : valueName.c_str(),
			0,
			REG_DWORD,
			reinterpret_cast<const BYTE*>(&data),
			sizeof(data));
	}
	else if (type == REG_QWORD) {
		ULONGLONG data = 0;
		if (!ParseUnsigned(text, data)) {
			strcpy_s(_editStatus, "Invalid QWORD. Use decimal or 0x-prefixed hex.");
			LoggerView::AddLog(LoggerView::UserModeLog, "Registry edit rejected invalid QWORD for %ws\\%ws",
				_selectedNode->FullPath.c_str(),
				value.IsDefault ? L"(Default)" : value.Name.c_str());
			return false;
		}
		status = ::RegSetValueExW(
			key.get(),
			valueName.empty() ? nullptr : valueName.c_str(),
			0,
			REG_QWORD,
			reinterpret_cast<const BYTE*>(&data),
			sizeof(data));
	}
	else if (type == REG_BINARY) {
		std::vector<BYTE> bytes;
		if (!ParseHexBytes(text, bytes)) {
			strcpy_s(_editStatus, "Invalid hex. Use pairs like 0A 1B 2C.");
			LoggerView::AddLog(LoggerView::UserModeLog, "Registry edit rejected invalid binary for %ws\\%ws",
				_selectedNode->FullPath.c_str(),
				value.IsDefault ? L"(Default)" : value.Name.c_str());
			return false;
		}
		status = ::RegSetValueExW(
			key.get(),
			valueName.empty() ? nullptr : valueName.c_str(),
			0,
			REG_BINARY,
			bytes.data(),
			static_cast<DWORD>(bytes.size()));
	}

	if (status != ERROR_SUCCESS) {
		sprintf_s(_editStatus, "RegSetValueEx failed: %lu", static_cast<unsigned long>(status));
		LoggerView::AddLog(LoggerView::UserModeLog, "Registry write failed for %ws\\%ws with status %lu",
			_selectedNode->FullPath.c_str(),
			value.IsDefault ? L"(Default)" : value.Name.c_str(),
			static_cast<unsigned long>(status));
		return false;
	}

	strcpy_s(_editStatus, "Saved.");
	LoggerView::AddLog(
		LoggerView::UserModeLog,
		"Updated registry value %ws under %ws",
		value.IsDefault ? L"(Default)" : value.Name.c_str(),
		_selectedNode->FullPath.c_str());
	return true;
}

std::vector<std::unique_ptr<RegistryView::RegistryNode>> RegistryView::CreateHiveRoots() const {
	struct HiveInfo {
		HKEY Root;
		const wchar_t* Name;
	};

	static const HiveInfo hives[] = {
		{ HKEY_CLASSES_ROOT, L"HKEY_CLASSES_ROOT" },
		{ HKEY_CURRENT_USER, L"HKEY_CURRENT_USER" },
		{ HKEY_LOCAL_MACHINE, L"HKEY_LOCAL_MACHINE" },
		{ HKEY_USERS, L"HKEY_USERS" },
		{ HKEY_CURRENT_CONFIG, L"HKEY_CURRENT_CONFIG" },
	};

	std::vector<std::unique_ptr<RegistryNode>> roots;
	roots.reserve(_countof(hives));
	for (const auto& hive : hives) {
		auto node = std::make_unique<RegistryNode>();
		node->Name = hive.Name;
		node->FullPath = hive.Name;
		node->RootKey = hive.Root;
		roots.push_back(std::move(node));
	}
	return roots;
}
