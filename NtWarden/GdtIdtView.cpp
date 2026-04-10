#include "pch.h"
#include "imgui.h"
#include "GdtIdtView.h"
#include "DriverHelper.h"
#include "RemoteClient.h"
#include "LoggerView.h"

namespace {

	struct GdtDecoded {
		unsigned long long Base;
		unsigned long Limit;
		unsigned char Type;
		unsigned char DPL;
		bool Present;
		bool Granularity;
		bool System;		// S bit (bit 44): 1 = code/data, 0 = system
	};

	GdtDecoded DecodeGdtEntry(unsigned long long raw) {
		GdtDecoded d{};

		// Base = bits [63:56] | [39:32] | [31:16]
		unsigned long long base_hi = (raw >> 56) & 0xFF;
		unsigned long long base_mid = (raw >> 32) & 0xFF;
		unsigned long long base_lo = (raw >> 16) & 0xFFFF;
		d.Base = (base_hi << 24) | (base_mid << 16) | base_lo;

		// Limit = bits [51:48] | [15:0]
		unsigned long limit_hi = static_cast<unsigned long>((raw >> 48) & 0x0F);
		unsigned long limit_lo = static_cast<unsigned long>(raw & 0xFFFF);
		d.Limit = (limit_hi << 16) | limit_lo;

		d.Type = static_cast<unsigned char>((raw >> 40) & 0x0F);
		d.System = ((raw >> 44) & 1) != 0;
		d.DPL = static_cast<unsigned char>((raw >> 45) & 0x03);
		d.Present = ((raw >> 47) & 1) != 0;
		d.Granularity = ((raw >> 55) & 1) != 0;

		if (d.Granularity)
			d.Limit = (d.Limit << 12) | 0xFFF;

		return d;
	}

	const char* GetGdtTypeString(const GdtDecoded& d) {
		if (!d.Present)
			return "Not Present";

		if (!d.System) {
			// System descriptor
			switch (d.Type) {
			case 0x2: return "LDT";
			case 0x9: return "TSS64 (Available)";
			case 0xB: return "TSS64 (Busy)";
			case 0xC: return "CallGate";
			case 0xE: return "InterruptGate";
			case 0xF: return "TrapGate";
			default:  return "System";
			}
		}

		// Code or Data descriptor (S=1)
		bool code = (d.Type & 0x8) != 0;
		if (code) {
			bool conforming = (d.Type & 0x4) != 0;
			bool readable = (d.Type & 0x2) != 0;
			if (conforming && readable) return "Code RXC";
			if (conforming)             return "Code XC";
			if (readable)               return "Code RX";
			return "Code X";
		}
		else {
			bool expandDown = (d.Type & 0x4) != 0;
			bool writable = (d.Type & 0x2) != 0;
			if (expandDown && writable) return "Data RWE";
			if (expandDown)             return "Data RE";
			if (writable)               return "Data RW";
			return "Data R";
		}
	}

	const char* GetIdtTypeString(unsigned char type) {
		switch (type) {
		case 0x5:  return "Task Gate";
		case 0xE:  return "Interrupt Gate";
		case 0xF:  return "Trap Gate";
		default:   return "Unknown";
		}
	}
}

void GdtIdtView::RefreshGdt() {
	if (_gdtLoading) return;
	_gdtLoading = true;
	_gdtFuture = std::async(std::launch::async, []() {
		GDT_INFO info{};
		if (!(RemoteClient::IsConnected() ? RemoteClient::GetGdt(info) : DriverHelper::GetGdt(info)))
			info.EntryCount = 0;
		return info;
	});
}

void GdtIdtView::RefreshIdt() {
	if (_idtLoading) return;
	_idtLoading = true;
	_idtFuture = std::async(std::launch::async, []() {
		IDT_INFO info{};
		if (!(RemoteClient::IsConnected() ? RemoteClient::GetIdt(info) : DriverHelper::GetIdt(info)))
			info.EntryCount = 0;
		return info;
	});
}

void GdtIdtView::RefreshNow() {
	RefreshGdt();
	RefreshIdt();
}

void GdtIdtView::BuildWindow() {
	if (_gdtLoading && _gdtFuture.valid() &&
		_gdtFuture.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
		_gdtInfo = _gdtFuture.get();
		_gdtLoaded = _gdtInfo.EntryCount > 0;
		_gdtLoading = false;
		if (_gdtLoaded)
	LoggerView::AddLog(LoggerView::UserModeLog, "Enumerated %u GDT entries", _gdtInfo.EntryCount);
	}
	if (_idtLoading && _idtFuture.valid() &&
		_idtFuture.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
		_idtInfo = _idtFuture.get();
		_idtLoaded = _idtInfo.EntryCount > 0;
		_idtLoading = false;
		if (_idtLoaded)
	LoggerView::AddLog(LoggerView::UserModeLog, "Enumerated %u IDT entries", _idtInfo.EntryCount);
	}

	if (ImGui::BeginTabBar("##DescTabs")) {
		if (ImGui::BeginTabItem("GDT")) {
			BuildGdtTab();
			ImGui::EndTabItem();
		}
		if (ImGui::BeginTabItem("IDT")) {
			BuildIdtTab();
			ImGui::EndTabItem();
		}
		ImGui::EndTabBar();
	}
}

void GdtIdtView::BuildGdtTab() {
	if (!_gdtLoaded) {
		RefreshGdt();
		if (_gdtLoading) {
			ImGui::TextDisabled("Reading GDT...");
			return;
		}
	}

	if (!_gdtLoaded) {
		ImGui::TextDisabled("Failed to read GDT");
		return;
	}

	ImGui::Text("GDT Base: 0x%016llX | Limit: 0x%04X | Entries: %u",
		_gdtInfo.Base, _gdtInfo.Limit, _gdtInfo.EntryCount);
	ImGui::Separator();

	if (ImGui::BeginTable("##GdtTable", 8,
		ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
		ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable)) {

		ImGui::TableSetupScrollFreeze(0, 1);
		ImGui::TableSetupColumn("Index");
		ImGui::TableSetupColumn("Raw Value");
		ImGui::TableSetupColumn("Base");
		ImGui::TableSetupColumn("Limit");
		ImGui::TableSetupColumn("Type");
		ImGui::TableSetupColumn("DPL");
		ImGui::TableSetupColumn("Present");
		ImGui::TableSetupColumn("Granularity");
		ImGui::TableHeadersRow();

		int count = static_cast<int>(_gdtInfo.EntryCount);
		ImGuiListClipper clipper;
		clipper.Begin(count);
		while (clipper.Step()) {
			for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
				auto raw = _gdtInfo.Entries[i];
				auto d = DecodeGdtEntry(raw);

				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0);
				ImGui::Text("%d", i);
				ImGui::TableSetColumnIndex(1);
				ImGui::Text("0x%016llX", raw);
				ImGui::TableSetColumnIndex(2);
				ImGui::Text("0x%016llX", d.Base);
				ImGui::TableSetColumnIndex(3);
				ImGui::Text("0x%08X", d.Limit);
				ImGui::TableSetColumnIndex(4);
				ImGui::TextUnformatted(GetGdtTypeString(d));
				ImGui::TableSetColumnIndex(5);
				ImGui::Text("%u", d.DPL);
				ImGui::TableSetColumnIndex(6);
				ImGui::TextUnformatted(d.Present ? "Yes" : "No");
				ImGui::TableSetColumnIndex(7);
				ImGui::TextUnformatted(d.Granularity ? "Page" : "Byte");
			}
		}

		ImGui::EndTable();
	}
}

void GdtIdtView::BuildIdtTab() {
	if (!_idtLoaded) {
		RefreshIdt();
		if (_idtLoading) {
			ImGui::TextDisabled("Reading IDT...");
			return;
		}
	}

	if (!_idtLoaded) {
		ImGui::TextDisabled("Failed to read IDT");
		return;
	}

	ImGui::Text("IDT Base: 0x%016llX | Limit: 0x%04X | Entries: %u",
		_idtInfo.Base, _idtInfo.Limit, _idtInfo.EntryCount);
	ImGui::Separator();

	if (ImGui::BeginTable("##IdtTable", 7,
		ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
		ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable)) {

		ImGui::TableSetupScrollFreeze(0, 1);
		ImGui::TableSetupColumn("Vector");
		ImGui::TableSetupColumn("ISR Address");
		ImGui::TableSetupColumn("Segment");
		ImGui::TableSetupColumn("IST");
		ImGui::TableSetupColumn("Type");
		ImGui::TableSetupColumn("DPL");
		ImGui::TableSetupColumn("Present");
		ImGui::TableHeadersRow();

		int count = static_cast<int>(_idtInfo.EntryCount);
		ImGuiListClipper clipper;
		clipper.Begin(count);
		while (clipper.Step()) {
			for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
				auto& entry = _idtInfo.Entries[i];

				bool isGray = !entry.Present;
				bool isYellow = entry.Present && entry.DPL == 3;

				if (isGray)
					ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.5f, 0.5f, 0.5f, 1.0f));
				else if (isYellow)
					ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 0.0f, 1.0f));

				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0);
				ImGui::Text("%d (0x%02X)", i, i);
				ImGui::TableSetColumnIndex(1);
				ImGui::Text("0x%016llX", entry.IsrAddress);
				ImGui::TableSetColumnIndex(2);
				ImGui::Text("0x%04X", entry.Segment);
				ImGui::TableSetColumnIndex(3);
				ImGui::Text("%u", entry.IST);
				ImGui::TableSetColumnIndex(4);
				ImGui::TextUnformatted(GetIdtTypeString(entry.Type));
				ImGui::TableSetColumnIndex(5);
				ImGui::Text("%u", entry.DPL);
				ImGui::TableSetColumnIndex(6);
				ImGui::TextUnformatted(entry.Present ? "Yes" : "No");

				if (isGray || isYellow)
					ImGui::PopStyleColor();
			}
		}

		ImGui::EndTable();
	}
}
