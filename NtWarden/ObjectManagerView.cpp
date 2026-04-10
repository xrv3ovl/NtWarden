#include "pch.h"
#include "ObjectManagerView.h"

#include "RemoteClient.h"
#include "LoggerView.h"
#include "Utils.h"
#include "imgui_internal.h"

#include <algorithm>
#include <cwctype>
#include <filesystem>
#include <string_view>
#include <wincodec.h>
#include <winternl.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040L
#endif

#ifndef DIRECTORY_QUERY
#define DIRECTORY_QUERY 0x0001
#endif

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes(p, n, a, r, s) \
	{ \
		(p)->Length = sizeof(OBJECT_ATTRIBUTES); \
		(p)->RootDirectory = r; \
		(p)->Attributes = a; \
		(p)->ObjectName = n; \
		(p)->SecurityDescriptor = s; \
		(p)->SecurityQualityOfService = nullptr; \
	}
#endif

typedef struct _OBJECT_DIRECTORY_INFORMATION_LOCAL {
	UNICODE_STRING Name;
	UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION_LOCAL, *POBJECT_DIRECTORY_INFORMATION_LOCAL;

extern "C" {
	NTSYSAPI NTSTATUS NTAPI NtOpenDirectoryObject(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
	NTSYSAPI NTSTATUS NTAPI NtQueryDirectoryObject(HANDLE DirectoryHandle, PVOID Buffer, ULONG Length, BOOLEAN ReturnSingleEntry, BOOLEAN RestartScan, PULONG Context, PULONG ReturnLength);
	NTSYSAPI NTSTATUS NTAPI NtOpenSymbolicLinkObject(PHANDLE LinkHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
	NTSYSAPI NTSTATUS NTAPI NtQuerySymbolicLinkObject(HANDLE LinkHandle, PUNICODE_STRING LinkTarget, PULONG ReturnedLength);
}

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

	std::string WideToUtf8(std::wstring_view text) {
		if (text.empty())
			return {};

		auto length = ::WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
		std::string utf8(length, '\0');
		::WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), utf8.data(), length, nullptr, nullptr);
		return utf8;
	}

	std::wstring ToLower(std::wstring_view text) {
		std::wstring lower(text.begin(), text.end());
		std::transform(lower.begin(), lower.end(), lower.begin(), [](wchar_t ch) {
			return static_cast<wchar_t>(std::towlower(ch));
			});
		return lower;
	}

	bool ContainsInsensitive(std::wstring_view value, const CString& filter) {
		if (filter.IsEmpty())
			return true;

		auto lower = ToLower(value);
		return lower.find(std::wstring(filter.GetString())) != std::wstring::npos;
	}

	std::wstring CombinePath(std::wstring_view parent, std::wstring_view child) {
		if (parent.empty() || parent == L"\\")
			return std::wstring(L"\\") + std::wstring(child);
		return std::wstring(parent) + L"\\" + std::wstring(child);
	}

	std::wstring ParentPath(std::wstring_view path) {
		if (path.empty() || path == L"\\")
			return L"\\";

		auto pos = path.find_last_of(L'\\');
		if (pos == std::wstring::npos || pos == 0)
			return L"\\";
		return std::wstring(path.substr(0, pos));
	}

	std::vector<ObjectManagerView::ObjectEntry> EnumDirectoryEntriesRemote(std::wstring_view path) {
		std::vector<ObjectManagerView::ObjectEntry> entries;
		auto narrow = WideToUtf8(path);
		auto remote = RemoteClient::GetObjDirectory(narrow);
		for (const auto& r : remote) {
			ObjectManagerView::ObjectEntry entry;
			int chars;
			chars = ::MultiByteToWideChar(CP_UTF8, 0, r.Name, -1, nullptr, 0);
			entry.Name.resize(chars > 0 ? chars - 1 : 0);
			if (chars > 0) ::MultiByteToWideChar(CP_UTF8, 0, r.Name, -1, entry.Name.data(), chars);
			chars = ::MultiByteToWideChar(CP_UTF8, 0, r.TypeName, -1, nullptr, 0);
			entry.TypeName.resize(chars > 0 ? chars - 1 : 0);
			if (chars > 0) ::MultiByteToWideChar(CP_UTF8, 0, r.TypeName, -1, entry.TypeName.data(), chars);
			chars = ::MultiByteToWideChar(CP_UTF8, 0, r.SymLinkTarget, -1, nullptr, 0);
			entry.SymbolicLinkTarget.resize(chars > 0 ? chars - 1 : 0);
			if (chars > 0) ::MultiByteToWideChar(CP_UTF8, 0, r.SymLinkTarget, -1, entry.SymbolicLinkTarget.data(), chars);
			chars = ::MultiByteToWideChar(CP_UTF8, 0, r.FullPath, -1, nullptr, 0);
			entry.FullPath.resize(chars > 0 ? chars - 1 : 0);
			if (chars > 0) ::MultiByteToWideChar(CP_UTF8, 0, r.FullPath, -1, entry.FullPath.data(), chars);
			entry.IsDirectory = r.IsDirectory != 0;
			entries.push_back(std::move(entry));
		}
		std::sort(entries.begin(), entries.end(), [](const auto& left, const auto& right) {
			if (left.IsDirectory != right.IsDirectory)
				return left.IsDirectory > right.IsDirectory;
			return ::_wcsicmp(left.Name.c_str(), right.Name.c_str()) < 0;
			});
		return entries;
	}

	std::vector<ObjectManagerView::ObjectEntry> EnumDirectoryEntries(std::wstring_view path) {
		if (RemoteClient::IsConnected())
			return EnumDirectoryEntriesRemote(path);

		std::vector<ObjectManagerView::ObjectEntry> entries;

		wil::unique_handle directory;
		UNICODE_STRING name;
		OBJECT_ATTRIBUTES attributes;
		std::wstring queryPath(path);
		::RtlInitUnicodeString(&name, queryPath.c_str());
		InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
		if (!NT_SUCCESS(::NtOpenDirectoryObject(directory.addressof(), DIRECTORY_QUERY, &attributes)))
			return entries;

		std::vector<BYTE> buffer(1 << 14);
		bool restart = true;
		ULONG context = 0;

		for (;;) {
			ULONG returnLength = 0;
			auto status = ::NtQueryDirectoryObject(
				directory.get(),
				buffer.data(),
				static_cast<ULONG>(buffer.size()),
				FALSE,
				restart,
				&context,
				&returnLength);
			if (!NT_SUCCESS(status))
				break;

			restart = false;
			auto* info = reinterpret_cast<POBJECT_DIRECTORY_INFORMATION_LOCAL>(buffer.data());
			for (auto item = info; item->Name.Buffer != nullptr; item++) {
				ObjectManagerView::ObjectEntry entry;
				entry.Name.assign(item->Name.Buffer, item->Name.Length / sizeof(WCHAR));
				entry.TypeName.assign(item->TypeName.Buffer, item->TypeName.Length / sizeof(WCHAR));
				entry.IsDirectory = entry.TypeName == L"Directory";
				entry.FullPath = CombinePath(path, entry.Name);

				if (entry.TypeName == L"SymbolicLink") {
					wil::unique_handle link;
					UNICODE_STRING linkName;
					OBJECT_ATTRIBUTES linkAttributes;
					::RtlInitUnicodeString(&linkName, entry.FullPath.c_str());
					InitializeObjectAttributes(&linkAttributes, &linkName, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
					if (NT_SUCCESS(::NtOpenSymbolicLinkObject(link.addressof(), GENERIC_READ, &linkAttributes))) {
						WCHAR targetBuffer[1024]{};
						UNICODE_STRING target{};
						target.Buffer = targetBuffer;
						target.MaximumLength = sizeof(targetBuffer);
						if (NT_SUCCESS(::NtQuerySymbolicLinkObject(link.get(), &target, nullptr)))
							entry.SymbolicLinkTarget.assign(target.Buffer, target.Length / sizeof(WCHAR));
					}
				}

				entries.push_back(std::move(entry));
			}
		}

		std::sort(entries.begin(), entries.end(), [](const auto& left, const auto& right) {
			if (left.IsDirectory != right.IsDirectory)
				return left.IsDirectory > right.IsDirectory;
			return ::_wcsicmp(left.Name.c_str(), right.Name.c_str()) < 0;
			});
		return entries;
	}

	std::unique_ptr<ObjectManagerView::DirectoryNode> BuildDirectoryTree(std::wstring_view path, std::wstring_view name) {
		auto node = std::make_unique<ObjectManagerView::DirectoryNode>();
		node->Name = name;
		node->FullPath = path;
		node->Objects = EnumDirectoryEntries(path);

		for (const auto& entry : node->Objects) {
			if (!entry.IsDirectory)
				continue;
			node->Children.push_back(BuildDirectoryTree(entry.FullPath, entry.Name));
		}
		return node;
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

	class ObjectIconCache final {
	public:
		static ObjectIconCache& Get() {
			static ObjectIconCache cache;
			return cache;
		}

		ID3D11ShaderResourceView* GetIcon(std::wstring_view typeName, bool isDirectory) {
			auto key = isDirectory ? std::wstring(L"Directory") : std::wstring(typeName);
			if (auto it = _loaded.find(key); it != _loaded.end())
				return it->second;

			auto file = L"Object.ico";
			if (auto icon = _typeIcons.find(key); icon != _typeIcons.end())
				file = icon->second.c_str();

			auto* view = CreateTextureFromIconFile(file);
			_loaded.insert({ key, view });
			return view;
		}

	private:
		ObjectIconCache() {
			_typeIcons = {
				{ L"Directory", L"directory.ico" },
				{ L"Process", L"process.ico" },
				{ L"Thread", L"thread.ico" },
				{ L"Key", L"key.ico" },
				{ L"Job", L"job.ico" },
				{ L"Desktop", L"desktop.ico" },
				{ L"ALPC Port", L"alpc.ico" },
				{ L"Mutant", L"mutex.ico" },
				{ L"Event", L"event.ico" },
				{ L"Semaphore", L"semaphore.ico" },
				{ L"PowerRequest", L"atom.ico" },
				{ L"Driver", L"car.ico" },
				{ L"Device", L"device.ico" },
				{ L"File", L"file.ico" },
				{ L"Callback", L"callback.ico" },
				{ L"Section", L"memory.ico" },
				{ L"Type", L"field.ico" },
				{ L"WindowStation", L"windowstation.ico" },
				{ L"SymbolicLink", L"link.ico" },
				{ L"Timer", L"timer.ico" },
				{ L"IRTimer", L"timer.ico" },
				{ L"Token", L"token.ico" },
				{ L"Session", L"user.ico" },
				{ L"DebugObject", L"debug.ico" },
				{ L"Profile", L"profile.ico" },
				{ L"CoreMessaging", L"message.ico" },
				{ L"CrossVmEvent", L"eventvm.ico" },
				{ L"FilterCommunicationPort", L"commport.ico" },
				{ L"CrossVmMutant", L"mutexvm.ico" },
				{ L"KeyedEvent", L"event-key.ico" },
				{ L"PsSiloContextPaged", L"silo.ico" },
				{ L"PsSiloContextNonPaged", L"silo.ico" },
				{ L"DxgkCompositionObject", L"directx.ico" },
				{ L"DxgkSharedResource", L"directx.ico" },
				{ L"DxgkSharedSyncObject", L"directx.ico" },
				{ L"DxgkDisplayManagerObject", L"directx.ico" },
				{ L"DxgkSharedProtectedSessionObject", L"directx.ico" },
				{ L"DxgkSharedKeyedMutexObject", L"directx.ico" },
				{ L"DxgkSharedSwapChainObject", L"directx.ico" },
				{ L"DxgkSharedBundleObject", L"directx.ico" },
				{ L"VRegConfigurationContext", L"registry.ico" },
				{ L"EtwRegistration", L"etwreg.ico" },
				{ L"EtwConsumer", L"etw.ico" },
				{ L"FilterConnectionPort", L"plug.ico" },
				{ L"Composition", L"component.ico" },
			};
		}

		std::unordered_map<std::wstring, std::wstring> _typeIcons;
		std::unordered_map<std::wstring, ID3D11ShaderResourceView*> _loaded;
	};

	bool CompareObjectEntries(const ObjectManagerView::ObjectEntry* left, const ObjectManagerView::ObjectEntry* right, int column, bool ascending) {
		auto compareStrings = [ascending](const std::wstring& a, const std::wstring& b) {
			auto result = ::_wcsicmp(a.c_str(), b.c_str());
			return ascending ? result < 0 : result > 0;
		};

		switch (column) {
		case 0: return compareStrings(left->Name, right->Name);
		case 1: return compareStrings(left->TypeName, right->TypeName);
		case 2: return compareStrings(left->SymbolicLinkTarget, right->SymbolicLinkTarget);
		case 3: return compareStrings(left->FullPath, right->FullPath);
		default: return compareStrings(left->Name, right->Name);
		}
	}
}

ObjectManagerView::ObjectManagerView() : ViewBase(8000) {
}

void ObjectManagerView::Refresh() {
	_root = BuildDirectoryTree(L"\\", L"\\");
	RebuildFlatCache();
	SelectDirectoryByPath(_selectedDirectoryPath.empty() ? std::wstring(L"\\") : _selectedDirectoryPath);
	if (_selectedDirectory == nullptr && _root)
		SelectDirectory(_root.get());
	LoggerView::AddLog(LoggerView::UserModeLog, "Enumerated %zu object manager entries", _flatObjects.size());
}

void ObjectManagerView::BuildWindow() {
	if (IsUpdateDue()) {
		Refresh();
		MarkUpdated();
	}
	BuildToolBar();
	BuildContent();
}

void ObjectManagerView::BuildToolBar() {
	ImGui::Separator();
	ImGui::Checkbox("List Mode", &_listMode);
	ImGui::SameLine();
	ImGui::Checkbox("Show Directories", &_showDirectories);
	ImGui::SameLine();
	if (!_selectedObjectPath.empty()) {
		if (ImGui::Button("Jump to Target"))
			JumpToTarget();
	}
	else {
		ImGui::BeginDisabled();
		ImGui::Button("Jump to Target");
		ImGui::EndDisabled();
	}
	ImGui::SameLine();
	DrawFilterToolbar();
	ImGui::SameLine();
	DrawUpdateIntervalToolbar("##ObjectManagerInterval", false);
}

void ObjectManagerView::BuildContent() {
	if (_root == nullptr) {
		ImGui::TextDisabled("Refreshing object namespace...");
		return;
	}

	if (_listMode) {
		BuildObjectListPane();
		return;
	}

	auto avail = ImGui::GetContentRegionAvail();
	_treePaneWidth = (std::clamp)(_treePaneWidth, 180.0f, (std::max)(180.0f, avail.x - 320.0f));

	ImGui::BeginChild("##ObjectTreePane", ImVec2(_treePaneWidth, 0), true);
	BuildTreePane();
	ImGui::EndChild();

	ImGui::SameLine();
	ImGui::InvisibleButton("##ObjectTreeSplitter", ImVec2(8.0f, avail.y));
	if (ImGui::IsItemActive())
		_treePaneWidth += ImGui::GetIO().MouseDelta.x;
	if (ImGui::IsItemHovered() || ImGui::IsItemActive())
		ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeEW);
	auto splitterColor = ImGui::GetColorU32(ImGui::IsItemActive() ? ImGuiCol_SeparatorActive :
		(ImGui::IsItemHovered() ? ImGuiCol_SeparatorHovered : ImGuiCol_Separator));
	ImGui::GetWindowDrawList()->AddRectFilled(ImGui::GetItemRectMin(), ImGui::GetItemRectMax(), splitterColor);

	ImGui::SameLine();
	ImGui::BeginChild("##ObjectListPane", ImVec2(0, 0), false);
	BuildObjectListPane();
	ImGui::EndChild();
}

void ObjectManagerView::BuildTreePane() {
	ImGui::TextUnformatted("Object Namespace");
	ImGui::Separator();
	BuildTreeNode(*_root);
}

void ObjectManagerView::BuildTreeNode(DirectoryNode& node) {
	ImGuiTreeNodeFlags flags = ImGuiTreeNodeFlags_OpenOnArrow | ImGuiTreeNodeFlags_SpanAvailWidth;
	if (node.Children.empty())
		flags |= ImGuiTreeNodeFlags_Leaf;
	if (&node == _selectedDirectory)
		flags |= ImGuiTreeNodeFlags_Selected;
	if (node.FullPath == L"\\")
		flags |= ImGuiTreeNodeFlags_DefaultOpen;

	auto label = WideToUtf8(node.FullPath == L"\\" ? std::wstring_view(L"\\") : std::wstring_view(node.Name));
	auto open = ImGui::TreeNodeEx(static_cast<void*>(&node), flags, "%s", label.c_str());
	if (ImGui::IsItemClicked())
		SelectDirectory(&node);

	if (open) {
		for (auto& child : node.Children)
			BuildTreeNode(*child);
		ImGui::TreePop();
	}
}

void ObjectManagerView::BuildObjectListPane() {
	std::vector<ObjectEntry*> rows;
	auto filter = GetFilterTextLower();

	if (_listMode) {
		rows.reserve(_flatObjects.size());
		for (auto* object : _flatObjects) {
			if (!_showDirectories && object->IsDirectory)
				continue;
			if (!ContainsInsensitive(object->Name, filter) &&
				!ContainsInsensitive(object->TypeName, filter) &&
				!ContainsInsensitive(object->FullPath, filter) &&
				!ContainsInsensitive(object->SymbolicLinkTarget, filter))
				continue;
			rows.push_back(object);
		}
	}
	else if (_selectedDirectory) {
		rows.reserve(_selectedDirectory->Objects.size());
		for (auto& object : _selectedDirectory->Objects) {
			if (!_showDirectories && object.IsDirectory)
				continue;
			if (!ContainsInsensitive(object.Name, filter) &&
				!ContainsInsensitive(object.TypeName, filter) &&
				!ContainsInsensitive(object.FullPath, filter) &&
				!ContainsInsensitive(object.SymbolicLinkTarget, filter))
				continue;
			rows.push_back(&object);
		}
	}

	auto scope = WideToUtf8(_listMode ? std::wstring_view(L"\\") :
		(_selectedDirectory ? std::wstring_view(_selectedDirectory->FullPath) : std::wstring_view(L"\\")));
	ImGui::Text("Path: %s", scope.c_str());
	ImGui::SameLine();
	ImGui::TextDisabled("| Items: %zu", rows.size());
	ImGui::Separator();

	if (ImGui::BeginTable("##ObjectManagerTable", 4,
		ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
		ImGuiTableFlags_ScrollX | ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable |
		ImGuiTableFlags_Sortable)) {
		ImGui::TableSetupScrollFreeze(1, 1);
		ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_DefaultSort);
		ImGui::TableSetupColumn("Type");
		ImGui::TableSetupColumn("Symbolic Link Target");
		ImGui::TableSetupColumn("Full Name");
		ImGui::TableHeadersRow();

		if (auto specs = ImGui::TableGetSortSpecs(); specs && specs->SpecsCount > 0) {
			auto column = specs->Specs[0].ColumnIndex;
			auto ascending = specs->Specs[0].SortDirection != ImGuiSortDirection_Descending;
			std::sort(rows.begin(), rows.end(), [column, ascending](const auto* left, const auto* right) {
				return CompareObjectEntries(left, right, column, ascending);
				});
			specs->SpecsDirty = false;
		}

		ImGuiListClipper clipper;
		clipper.Begin(static_cast<int>(rows.size()));
		while (clipper.Step()) {
			for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
				auto* row = rows[i];
				auto name = WideToUtf8(row->Name);
				auto type = WideToUtf8(row->TypeName);
				auto target = WideToUtf8(row->SymbolicLinkTarget);
				auto fullPath = WideToUtf8(row->FullPath);

				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0);
				if (auto* icon = ObjectIconCache::Get().GetIcon(row->TypeName, row->IsDirectory)) {
					ImGui::Image(icon, ImVec2(16, 16));
					ImGui::SameLine();
				}
				if (ImGui::Selectable((name + "##" + fullPath).c_str(), _selectedObjectPath == row->FullPath, ImGuiSelectableFlags_SpanAllColumns))
					_selectedObjectPath = row->FullPath;

				if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
					if (row->IsDirectory)
						SelectDirectoryByPath(row->FullPath);
					else if (!row->SymbolicLinkTarget.empty())
						JumpToTarget();
				}

				if (ImGui::BeginPopupContextItem()) {
					if (ImGui::MenuItem("Copy Name"))
						ImGui::SetClipboardText(name.c_str());
					if (ImGui::MenuItem("Copy Full Path"))
						ImGui::SetClipboardText(fullPath.c_str());
					if (!target.empty()) {
						if (ImGui::MenuItem("Copy Link Target"))
							ImGui::SetClipboardText(target.c_str());
						if (ImGui::MenuItem("Jump To Target"))
							JumpToTarget();
					}
					ImGui::EndPopup();
				}

				ImGui::TableSetColumnIndex(1);
				ImGui::TextUnformatted(type.c_str());
				ImGui::TableSetColumnIndex(2);
				ImGui::TextUnformatted(target.c_str());
				ImGui::TableSetColumnIndex(3);
				ImGui::TextUnformatted(fullPath.c_str());
			}
		}

		ImGui::EndTable();
	}
}

void ObjectManagerView::CollectObjects(DirectoryNode& node) {
	for (auto& object : node.Objects)
		_flatObjects.push_back(&object);
	for (auto& child : node.Children)
		CollectObjects(*child);
}

void ObjectManagerView::RebuildFlatCache() {
	_flatObjects.clear();
	if (_root)
		CollectObjects(*_root);
}

void ObjectManagerView::SelectDirectory(DirectoryNode* node) {
	_selectedDirectory = node;
	if (node)
		_selectedDirectoryPath = node->FullPath;
}

void ObjectManagerView::SelectDirectoryByPath(const std::wstring& path) {
	if (_root == nullptr)
		return;
	if (auto* node = FindDirectoryByPath(*_root, path))
		SelectDirectory(node);
	else
		SelectDirectory(_root.get());
}

ObjectManagerView::DirectoryNode* ObjectManagerView::FindDirectoryByPath(DirectoryNode& node, const std::wstring& path) {
	if (node.FullPath == path)
		return &node;

	for (auto& child : node.Children) {
		if (auto* found = FindDirectoryByPath(*child, path))
			return found;
	}
	return nullptr;
}

bool ObjectManagerView::JumpToTarget() {
	if (_selectedObjectPath.empty())
		return false;

	for (auto* object : _flatObjects) {
		if (object->FullPath != _selectedObjectPath || object->SymbolicLinkTarget.empty())
			continue;

		for (auto* candidate : _flatObjects) {
			if (candidate->FullPath == object->SymbolicLinkTarget) {
				SelectDirectoryByPath(ParentPath(candidate->FullPath));
				_selectedObjectPath = candidate->FullPath;
				return true;
			}
		}

		SelectDirectoryByPath(object->SymbolicLinkTarget);
		_selectedObjectPath.clear();
		return true;
	}
	return false;
}
