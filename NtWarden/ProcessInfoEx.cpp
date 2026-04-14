#include "pch.h"
#include "ProcessInfoEx.h"
#include "Processes.h"
#include "colors.h"
#include "ProcessManager.h"
#include "Globals.h"
#include "Settings.h"
#include "ProcessColor.h"
#include <wincodec.h>
#include "resource.h"
#include "LoggerView.h"
#include <atomic>
#include <thread>
#include <mutex>
#include <unordered_map>

std::pair<const ImVec4&, const ImVec4&> ProcessInfoEx::GetColors(WinSys::ProcessManager& pm) const
{
	using namespace ImGui;
	auto& colors = Globals::Get().GetSettings().ProcessColors;

	if (colors[Settings::DeletedObjects].Enabled && IsTerminated())
		return { colors[Settings::DeletedObjects].Color, colors[Settings::DeletedObjects].TextColor };

	if (colors[Settings::NewObjects].Enabled && IsNew())
		return { colors[Settings::NewObjects].Color, colors[Settings::NewObjects].TextColor };

	auto attributes = GetAttributes(pm);
	if (colors[Settings::Manageed].Enabled && (attributes & ProcessAttributes::Managed) == ProcessAttributes::Managed)
		return { colors[Settings::Manageed].Color, colors[Settings::Manageed].TextColor };
	if (colors[Settings::Immersive].Enabled && (attributes & ProcessAttributes::Immersive) == ProcessAttributes::Immersive)
		return { colors[Settings::Immersive].Color, colors[Settings::Immersive].TextColor };
	if (colors[Settings::Secure].Enabled && (attributes & ProcessAttributes::Secure) == ProcessAttributes::Secure)
		return { colors[Settings::Secure].Color, colors[Settings::Secure].TextColor };
	if (colors[Settings::Protected].Enabled && (attributes & ProcessAttributes::Protected) == ProcessAttributes::Protected)
		return { colors[Settings::Protected].Color, colors[Settings::Protected].TextColor };
	if (colors[Settings::Services].Enabled && (attributes & ProcessAttributes::Service) == ProcessAttributes::Service)
		return { colors[Settings::Services].Color, colors[Settings::Services].TextColor };
	if (colors[Settings::InJob].Enabled && (attributes & ProcessAttributes::InJob) == ProcessAttributes::InJob)
		return { colors[Settings::InJob].Color, colors[Settings::InJob].TextColor };

	return { ImVec4(-1, 0, 0, 0), ImVec4() };
}

ProcessAttributes ProcessInfoEx::GetAttributes(WinSys::ProcessManager& pm) const
{
	ConsumeMetadataResult();
	if (_attributes == ProcessAttributes::NotComputed) {
		auto parent = pm.GetProcessById(_pi->ParentId);
		bool parentIsServices = parent && ::_wcsicmp(parent->GetImageName().c_str(), L"services.exe") == 0;
		StartMetadataLoad(parentIsServices);
		return ProcessAttributes::None;
	}
	return _attributes;
}

const std::wstring& ProcessInfoEx::UserName() const
{
	ConsumeMetadataResult();
	if (_username.empty())
		StartMetadataLoad(false);
	return _username;
}

bool ProcessInfoEx::Update()
{
	if (!_isNew && !_isTerminated)
		return false;

	bool term = _isTerminated;
	if (::GetTickCount64() > _expiryTime)
	{
		_isTerminated = _isNew = false;
		return term;
	}
	return false;
}

void ProcessInfoEx::New(uint32_t ms)
{
	_isNew = true;
	_expiryTime = ::GetTickCount64() + ms;
}

void ProcessInfoEx::Term(uint32_t ms)
{
	_isNew = false;
	_isTerminated = true;
	_expiryTime = ::GetTickCount64() + ms;
}

// Convert NT device path (\Device\HarddiskVolume2\...) to DOS path (C:\...)
static std::wstring NtPathToDosPath(const std::wstring& ntPath) {
	if (ntPath.find(L"\\Device\\") != 0)
		return ntPath;

	WCHAR drives[512]{};
	if (::GetLogicalDriveStringsW(_countof(drives) - 1, drives) == 0)
		return ntPath;

	for (WCHAR* drive = drives; *drive; drive += wcslen(drive) + 1) {
		WCHAR letter[3] = { drive[0], L':', L'\0' };
		WCHAR deviceName[MAX_PATH]{};
		if (::QueryDosDeviceW(letter, deviceName, MAX_PATH) > 0) {
			size_t devLen = wcslen(deviceName);
			if (_wcsnicmp(ntPath.c_str(), deviceName, devLen) == 0 &&
				ntPath.size() > devLen && ntPath[devLen] == L'\\') {
				return std::wstring(letter) + ntPath.substr(devLen);
			}
		}
	}
	return ntPath;
}

namespace {
	struct IconPixels {
		UINT Width{ 0 };
		UINT Height{ 0 };
		std::vector<BYTE> Pixels;
		std::wstring ResolvedPath;
		bool Success{ false };
	};

	std::wstring ResolveExecutablePathForIcon(DWORD pid, const std::wstring& nativeImagePath) {
		if (pid != 0) {
			auto process = WinSys::Process::OpenById(pid, WinSys::ProcessAccessMask::QueryLimitedInformation);
			if (process) {
				auto fullName = process->GetFullImageName();
				if (!fullName.empty())
					return fullName;
			}
		}

		if (!nativeImagePath.empty())
			return NtPathToDosPath(nativeImagePath);

		return {};
	}

	IconPixels LoadProcessIconPixels(DWORD pid, const std::wstring& nativeImagePath) {
		IconPixels result;
		result.ResolvedPath = ResolveExecutablePathForIcon(pid, nativeImagePath);

		HRESULT initHr = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
		const bool shouldUninit = SUCCEEDED(initHr);

		CComPtr<IWICImagingFactory> spFactory;
		if (FAILED(::CoCreateInstance(CLSID_WICImagingFactory2, nullptr, CLSCTX_INPROC_SERVER,
			__uuidof(IWICImagingFactory2), reinterpret_cast<void**>(&spFactory))))
		{
			::CoCreateInstance(CLSID_WICImagingFactory1, nullptr, CLSCTX_INPROC_SERVER,
				__uuidof(IWICImagingFactory), reinterpret_cast<void**>(&spFactory));
		}
		if (!spFactory) {
			if (shouldUninit)
				::CoUninitialize();
			return result;
		}

		static HICON hAppIcon = ::LoadIcon(nullptr, IDI_APPLICATION);
		HICON hIcon = nullptr;

		if (!result.ResolvedPath.empty()) {
			SHFILEINFOW sfi{};
			if (::SHGetFileInfoW(result.ResolvedPath.c_str(), FILE_ATTRIBUTE_NORMAL, &sfi, sizeof(sfi),
				SHGFI_ICON | SHGFI_SMALLICON)) {
				hIcon = sfi.hIcon;
			}
			else if (::SHGetFileInfoW(result.ResolvedPath.c_str(), FILE_ATTRIBUTE_NORMAL, &sfi, sizeof(sfi),
				SHGFI_ICON | SHGFI_SMALLICON | SHGFI_USEFILEATTRIBUTES)) {
				hIcon = sfi.hIcon;
			}
		}

		if (hIcon == reinterpret_cast<HICON>(1)) {
			::DestroyIcon(hIcon);
			hIcon = hAppIcon;
		}
		else if (hIcon == nullptr) {
			hIcon = hAppIcon;
		}

		if (!hIcon) {
			if (shouldUninit)
				::CoUninitialize();
			return result;
		}

		CComPtr<IWICBitmap> spBitmap;
		auto hr = spFactory->CreateBitmapFromHICON(hIcon, &spBitmap);
		if (hIcon != hAppIcon)
			::DestroyIcon(hIcon);
		if (FAILED(hr)) {
			if (shouldUninit)
				::CoUninitialize();
			return result;
		}

		UINT width = 0, height = 0;
		hr = spBitmap->GetSize(&width, &height);
		if (FAILED(hr) || width == 0 || height == 0) {
			if (shouldUninit)
				::CoUninitialize();
			return result;
		}

		CComPtr<IWICBitmapLock> spLock;
		hr = spBitmap->Lock(nullptr, WICBitmapLockRead, &spLock);
		if (FAILED(hr)) {
			if (shouldUninit)
				::CoUninitialize();
			return result;
		}

		UINT bufferSize = 0;
		WICInProcPointer pData = nullptr;
		hr = spLock->GetDataPointer(&bufferSize, &pData);
		if (FAILED(hr) || pData == nullptr || bufferSize == 0) {
			if (shouldUninit)
				::CoUninitialize();
			return result;
		}

		result.Width = width;
		result.Height = height;
		result.Pixels.assign(pData, pData + bufferSize);
		result.Success = true;

		if (shouldUninit)
			::CoUninitialize();
		return result;
	}

	struct ProcessMetadataResult {
		std::wstring ExecutablePath;
		std::wstring UserName;
		ProcessAttributes Attributes{ ProcessAttributes::None };
	};

	ProcessMetadataResult LoadProcessMetadata(DWORD pid, const std::wstring& nativeImagePath, bool parentIsServices) {
		ProcessMetadataResult result;
		result.Attributes = ProcessAttributes::None;

		if (pid <= 4)
			result.UserName = L"NT AUTHORITY\\SYSTEM";

		auto process = pid == 0
			? nullptr
			: WinSys::Process::OpenById(pid, WinSys::ProcessAccessMask::QueryInformation | WinSys::ProcessAccessMask::QueryLimitedInformation);

		if (process) {
			result.UserName = process->GetUserNameW();
		}
		if (result.UserName.empty())
			result.UserName = L"<access denied>";

		if (process) {
			auto fullName = process->GetFullImageName();
			if (!fullName.empty())
				result.ExecutablePath = fullName;

			if (process->IsManaged())
				result.Attributes |= ProcessAttributes::Managed;
			if (process->IsProtected())
				result.Attributes |= ProcessAttributes::Protected;
			if (process->IsImmersive())
				result.Attributes |= ProcessAttributes::Immersive;
			if (process->IsSecure())
				result.Attributes |= ProcessAttributes::Secure;
			if (process->IsInJob())
				result.Attributes |= ProcessAttributes::InJob;
		}

		if (result.ExecutablePath.empty() && !nativeImagePath.empty())
			result.ExecutablePath = NtPathToDosPath(nativeImagePath);

		if (parentIsServices)
			result.Attributes |= ProcessAttributes::Service;

		return result;
	}
}

struct ProcessInfoEx::IconTaskState {
	std::atomic<bool> Ready{ false };
	IconPixels Result;
};

struct ProcessInfoEx::MetadataTaskState {
	std::atomic<bool> Ready{ false };
	ProcessMetadataResult Result;
};

void ProcessInfoEx::ConsumeMetadataResult() const {
	if (!_metadataTask || !_metadataTask->Ready.load(std::memory_order_acquire))
		return;

	auto task = _metadataTask;
	_metadataTask.reset();

	if (_executablePath.empty())
		_executablePath = task->Result.ExecutablePath;
	if (_username.empty())
		_username = task->Result.UserName;
	if (_attributes == ProcessAttributes::NotComputed)
		_attributes = task->Result.Attributes;
}

void ProcessInfoEx::StartMetadataLoad(bool parentIsServices) const {
	if (_metadataTask)
		return;
	if (_attributes != ProcessAttributes::NotComputed && !_username.empty() && !_executablePath.empty())
		return;

	_metadataTask = std::make_shared<MetadataTaskState>();
	auto task = _metadataTask;
	DWORD pid = _pi->Id;
	auto nativePath = _pi->GetNativeImagePath();
	std::thread([task, pid, nativePath = std::move(nativePath), parentIsServices]() mutable {
		task->Result = LoadProcessMetadata(pid, nativePath, parentIsServices);
		task->Ready.store(true, std::memory_order_release);
		}).detach();
}

const std::wstring& ProcessInfoEx::GetExecutablePath() const
{
	ConsumeMetadataResult();
	if (_executablePath.empty() && _pi->Id != 0)
		StartMetadataLoad(false);
	return _executablePath;
}

// Shared icon cache: one texture per unique executable path
extern ID3D11Device* g_pd3dDevice;

namespace {
	struct SharedIconEntry {
		enum class State { Loading, Ready, Failed };
		State LoadState{ State::Loading };
		CComPtr<ID3D11ShaderResourceView> SRV;
		std::shared_ptr<ProcessInfoEx::IconTaskState> Task;
	};

	std::mutex g_iconCacheMutex;
	std::unordered_map<std::wstring, std::shared_ptr<SharedIconEntry>> g_iconCache;

	// Try to finalize a cache entry that's still loading (must be called on main thread)
	bool TryFinalizeIconEntry(SharedIconEntry& entry) {
		if (entry.LoadState != SharedIconEntry::State::Loading || !entry.Task)
			return false;
		if (!entry.Task->Ready.load(std::memory_order_acquire))
			return false;

		auto task = entry.Task;
		entry.Task.reset();

		if (!task->Result.Success || g_pd3dDevice == nullptr) {
			entry.LoadState = SharedIconEntry::State::Failed;
			return true;
		}

		D3D11_TEXTURE2D_DESC desc = {};
		desc.Width = task->Result.Width;
		desc.Height = task->Result.Height;
		desc.MipLevels = 1;
		desc.ArraySize = 1;
		desc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
		desc.SampleDesc.Count = 1;
		desc.Usage = D3D11_USAGE_DEFAULT;
		desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;

		CComPtr<ID3D11Texture2D> pTexture;
		D3D11_SUBRESOURCE_DATA subResource = {};
		subResource.pSysMem = task->Result.Pixels.data();
		subResource.SysMemPitch = desc.Width * 4;
		auto hr = g_pd3dDevice->CreateTexture2D(&desc, &subResource, &pTexture);
		if (FAILED(hr)) {
			entry.LoadState = SharedIconEntry::State::Failed;
			return true;
		}

		D3D11_SHADER_RESOURCE_VIEW_DESC srvDesc = {};
		srvDesc.Format = desc.Format;
		srvDesc.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D;
		srvDesc.Texture2D.MipLevels = desc.MipLevels;
		srvDesc.Texture2D.MostDetailedMip = 0;
		hr = g_pd3dDevice->CreateShaderResourceView(pTexture, &srvDesc, &entry.SRV);
		if (FAILED(hr)) {
			entry.LoadState = SharedIconEntry::State::Failed;
			return true;
		}

		entry.LoadState = SharedIconEntry::State::Ready;
		return true;
	}
}

ID3D11ShaderResourceView* ProcessInfoEx::Icon(bool allowCreate) const
{
	// Fast path: already resolved for this instance
	if (m_spIcon != nullptr)
		return m_spIcon.p;

	if (_iconState == IconLoadState::Failed)
		return nullptr;

	// Resolve the executable path (needed as cache key)
	ConsumeMetadataResult();
	auto nativePath = _pi->GetNativeImagePath();
	const auto& path = _executablePath.empty() ? nativePath : _executablePath;

	// System Idle Process / System — no icon
	if (path.empty() && _pi->Id <= 4) {
		_iconState = IconLoadState::Failed;
		return nullptr;
	}

	// Build cache key from resolved path (normalized to lowercase)
	std::wstring cacheKey;
	if (!path.empty()) {
		cacheKey = path;
		for (auto& c : cacheKey) c = towlower(c);
	}

	// If we have a cache key, try the shared cache
	if (!cacheKey.empty()) {
		std::shared_ptr<SharedIconEntry> entry;
		SharedIconEntry::State finalState = SharedIconEntry::State::Loading;
		{
			std::lock_guard<std::mutex> lock(g_iconCacheMutex);
			auto it = g_iconCache.find(cacheKey);
			if (it != g_iconCache.end()) {
				entry = it->second;
				// Finalize under the lock so only one caller creates D3D resources
				if (entry->LoadState == SharedIconEntry::State::Loading)
					TryFinalizeIconEntry(*entry);
				finalState = entry->LoadState;
			}
			else if (allowCreate) {
				// First request for this path — create cache entry and start loading
				entry = std::make_shared<SharedIconEntry>();
				entry->Task = std::make_shared<IconTaskState>();
				g_iconCache[cacheKey] = entry;

				auto task = entry->Task;
				DWORD pid = _pi->Id;
				auto nativePathCopy = _pi->GetNativeImagePath();
				std::thread([task, pid, nativePathCopy = std::move(nativePathCopy)]() mutable {
					task->Result = LoadProcessIconPixels(pid, nativePathCopy);
					task->Ready.store(true, std::memory_order_release);
					}).detach();

				_iconState = IconLoadState::Loading;
				return nullptr;
			}
		}

		if (entry) {
			if (finalState == SharedIconEntry::State::Ready) {
				m_spIcon = entry->SRV;
				_iconState = IconLoadState::Ready;
				return m_spIcon.p;
			}
			if (finalState == SharedIconEntry::State::Failed) {
				_iconState = IconLoadState::Failed;
				return nullptr;
			}
			// Still loading
			_iconState = IconLoadState::Loading;
			return nullptr;
		}

		return nullptr;
	}

	// No path resolved yet — fall back to per-instance loading (no caching)
	if (!allowCreate)
		return nullptr;

	if (_iconState == IconLoadState::NotRequested) {
		_iconState = IconLoadState::Loading;
		auto task = std::make_shared<IconTaskState>();
		_iconFallbackTask = task;
		DWORD pid = _pi->Id;
		auto nativePathCopy = _pi->GetNativeImagePath();
		std::thread([task, pid, nativePathCopy = std::move(nativePathCopy)]() mutable {
			task->Result = LoadProcessIconPixels(pid, nativePathCopy);
			task->Ready.store(true, std::memory_order_release);
			}).detach();
	}

	// Check if per-instance fallback task completed
	if (_iconFallbackTask && _iconFallbackTask->Ready.load(std::memory_order_acquire)) {
		auto task = _iconFallbackTask;
		_iconFallbackTask.reset();

		if (!task->Result.Success || g_pd3dDevice == nullptr) {
			_iconState = IconLoadState::Failed;
			return nullptr;
		}

		if (!task->Result.ResolvedPath.empty() && _executablePath.empty())
			_executablePath = task->Result.ResolvedPath;

		D3D11_TEXTURE2D_DESC desc = {};
		desc.Width = task->Result.Width;
		desc.Height = task->Result.Height;
		desc.MipLevels = 1;
		desc.ArraySize = 1;
		desc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
		desc.SampleDesc.Count = 1;
		desc.Usage = D3D11_USAGE_DEFAULT;
		desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;

		CComPtr<ID3D11Texture2D> pTexture;
		D3D11_SUBRESOURCE_DATA subResource = {};
		subResource.pSysMem = task->Result.Pixels.data();
		subResource.SysMemPitch = desc.Width * 4;
		auto hr = g_pd3dDevice->CreateTexture2D(&desc, &subResource, &pTexture);
		if (FAILED(hr)) {
			_iconState = IconLoadState::Failed;
			return nullptr;
		}

		D3D11_SHADER_RESOURCE_VIEW_DESC srvDesc = {};
		srvDesc.Format = desc.Format;
		srvDesc.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D;
		srvDesc.Texture2D.MipLevels = desc.MipLevels;
		srvDesc.Texture2D.MostDetailedMip = 0;
		hr = g_pd3dDevice->CreateShaderResourceView(pTexture, &srvDesc, &m_spIcon);
		if (FAILED(hr)) {
			_iconState = IconLoadState::Failed;
			return nullptr;
		}

		_iconState = IconLoadState::Ready;
		return m_spIcon.p;
	}

	return nullptr;
}
