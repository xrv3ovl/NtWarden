#include "pch.h"
#include "imgui.h"
#include "RootCertificatesView.h"
#include "RemoteClient.h"
#include "LoggerView.h"
#include <wincrypt.h>

#pragma comment(lib, "Crypt32.lib")

using namespace ImGui;

namespace {
	std::wstring GetCertName(PCCERT_CONTEXT cert, DWORD type, DWORD flags = 0) {
		DWORD chars = ::CertGetNameString(cert, type, flags, nullptr, nullptr, 0);
		if (chars == 0)
			return L"";

		std::wstring text(chars, L'\0');
		::CertGetNameString(cert, type, flags, nullptr, text.data(), chars);
		if (!text.empty() && text.back() == L'\0')
			text.pop_back();
		return text;
	}

	std::wstring FormatFileTime(const FILETIME& ft) {
		SYSTEMTIME st{};
		if (!::FileTimeToSystemTime(&ft, &st))
			return L"";

		CStringW text;
		text.Format(L"%04u-%02u-%02u", st.wYear, st.wMonth, st.wDay);
		return std::wstring(text);
	}

	std::wstring GetThumbprint(PCCERT_CONTEXT cert) {
		DWORD size = 0;
		if (!::CertGetCertificateContextProperty(cert, CERT_SHA1_HASH_PROP_ID, nullptr, &size) || size == 0)
			return L"";

		std::vector<BYTE> hash(size);
		if (!::CertGetCertificateContextProperty(cert, CERT_SHA1_HASH_PROP_ID, hash.data(), &size))
			return L"";

		CStringW text;
		for (DWORD i = 0; i < size; i++) {
			CStringW byteText;
			byteText.Format(L"%02X", hash[i]);
			text += byteText;
			if (i + 1 < size)
				text += L":";
		}
		return std::wstring(text);
	}

	void AddCertificatesFromStore(HCERTSTORE store, PCWSTR storeName, std::vector<RootCertificatesView::CertificateInfo>& output) {
		PCCERT_CONTEXT cert = nullptr;
		while ((cert = ::CertEnumCertificatesInStore(store, cert)) != nullptr) {
			RootCertificatesView::CertificateInfo info;
			info.Subject = GetCertName(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE);
			info.Issuer = GetCertName(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG);
			info.Thumbprint = GetThumbprint(cert);
			info.Store = storeName;
			info.Expires = FormatFileTime(cert->pCertInfo->NotAfter);
			output.push_back(std::move(info));
		}
	}
}

void RootCertificatesView::RefreshNow() {
	Refresh();
	MarkUpdated();
}

RootCertificatesView::RootCertificatesView() : ViewBase(0) {
	Refresh();
}

void RootCertificatesView::BuildWindow() {
	BuildToolBar();
	BuildTable();
}

void RootCertificatesView::Refresh() {
	_certificates.clear();

	if (RemoteClient::IsConnected()) {
		auto remote = RemoteClient::GetCertificates();
		for (const auto& c : remote) {
			CertificateInfo info;
			int chars;
			chars = ::MultiByteToWideChar(CP_UTF8, 0, c.Subject, -1, nullptr, 0);
			info.Subject.resize(chars > 0 ? chars - 1 : 0);
			if (chars > 0) ::MultiByteToWideChar(CP_UTF8, 0, c.Subject, -1, info.Subject.data(), chars);
			chars = ::MultiByteToWideChar(CP_UTF8, 0, c.Issuer, -1, nullptr, 0);
			info.Issuer.resize(chars > 0 ? chars - 1 : 0);
			if (chars > 0) ::MultiByteToWideChar(CP_UTF8, 0, c.Issuer, -1, info.Issuer.data(), chars);
			chars = ::MultiByteToWideChar(CP_UTF8, 0, c.Store, -1, nullptr, 0);
			info.Store.resize(chars > 0 ? chars - 1 : 0);
			if (chars > 0) ::MultiByteToWideChar(CP_UTF8, 0, c.Store, -1, info.Store.data(), chars);
			chars = ::MultiByteToWideChar(CP_UTF8, 0, c.Expires, -1, nullptr, 0);
			info.Expires.resize(chars > 0 ? chars - 1 : 0);
			if (chars > 0) ::MultiByteToWideChar(CP_UTF8, 0, c.Expires, -1, info.Expires.data(), chars);
			chars = ::MultiByteToWideChar(CP_UTF8, 0, c.Thumbprint, -1, nullptr, 0);
			info.Thumbprint.resize(chars > 0 ? chars - 1 : 0);
			if (chars > 0) ::MultiByteToWideChar(CP_UTF8, 0, c.Thumbprint, -1, info.Thumbprint.data(), chars);
			_certificates.push_back(std::move(info));
		}
		LoggerView::AddLog(LoggerView::UserModeLog, "Loaded %d root certificates (remote)", static_cast<int>(_certificates.size()));
		return;
	}

	struct StoreTarget {
		DWORD Location;
		PCWSTR Name;
		PCWSTR Label;
	};

	static constexpr StoreTarget stores[] = {
		{ CERT_SYSTEM_STORE_LOCAL_MACHINE, L"ROOT", L"Local Machine" },
		{ CERT_SYSTEM_STORE_CURRENT_USER, L"ROOT", L"Current User" },
	};

	for (const auto& target : stores) {
		auto store = ::CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, target.Location, target.Name);
		if (!store)
			continue;

		AddCertificatesFromStore(store, target.Label, _certificates);
		::CertCloseStore(store, 0);
	}

	LoggerView::AddLog(LoggerView::UserModeLog, "Loaded %d root certificates", static_cast<int>(_certificates.size()));
}

void RootCertificatesView::BuildToolBar() {
	DrawFilterToolbar(200.0f);
}

void RootCertificatesView::BuildTable() {
	auto filter = GetFilterTextLower();
	if (BeginTable("rootCertTable", 5, ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable |
		ImGuiTableFlags_ScrollX | ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_Hideable |
		ImGuiTableFlags_NoSavedSettings)) {
		TableSetupScrollFreeze(1, 1);
		TableSetupColumn("Subject");
		TableSetupColumn("Issuer");
		TableSetupColumn("Store");
		TableSetupColumn("Expires");
		TableSetupColumn("Thumbprint");
		TableHeadersRow();

		for (const auto& cert : _certificates) {
			if (!filter.IsEmpty()) {
				CString haystack((cert.Subject + L" " + cert.Issuer + L" " + cert.Thumbprint + L" " + cert.Store).c_str());
				haystack.MakeLower();
				if (haystack.Find(filter) < 0)
					continue;
			}

			TableNextRow();
			TableSetColumnIndex(0);
			Text("%ws", cert.Subject.c_str());
			TableSetColumnIndex(1);
			Text("%ws", cert.Issuer.c_str());
			TableSetColumnIndex(2);
			Text("%ws", cert.Store.c_str());
			TableSetColumnIndex(3);
			Text("%ws", cert.Expires.c_str());
			TableSetColumnIndex(4);
			Text("%ws", cert.Thumbprint.c_str());
		}

		EndTable();
	}
}
