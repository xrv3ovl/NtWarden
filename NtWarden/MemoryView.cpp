#include "pch.h"
#include "imgui.h"
#include "MemoryView.h"
#include "DriverHelper.h"
#include "RemoteClient.h"
#include "LoggerView.h"
#include "Utils.h"
#include <cctype>

using namespace ImGui;

namespace {
	static bool ParseHexU64(const char* text, unsigned long long& value) {
		char* end = nullptr;
		if (text == nullptr || *text == '\0')
			return false;
		value = _strtoui64(text, &end, 16);
		return end != text && *end == '\0';
	}

	static bool ParseHexBytes(const char* text, std::vector<unsigned char>& bytes) {
		int highNibble;
		const unsigned char* ptr;

		bytes.clear();
		highNibble = -1;
		ptr = (const unsigned char*)text;
		while (ptr && *ptr) {
			int value;
			if (isspace(*ptr) || *ptr == ',' || *ptr == ';') {
				ptr++;
				continue;
			}
			if (*ptr >= '0' && *ptr <= '9')
				value = *ptr - '0';
			else if (*ptr >= 'a' && *ptr <= 'f')
				value = *ptr - 'a' + 10;
			else if (*ptr >= 'A' && *ptr <= 'F')
				value = *ptr - 'A' + 10;
			else
				return false;

			if (highNibble < 0) {
				highNibble = value;
			}
			else {
				bytes.push_back((unsigned char)((highNibble << 4) | value));
				highNibble = -1;
			}
			ptr++;
		}

		return highNibble < 0;
	}

	static char Printable(unsigned char value) {
		return value >= 32 && value <= 126 ? (char)value : '.';
	}
}

void MemoryView::ResetReadState() {
	RtlZeroMemory(&_readResult, sizeof(_readResult));
	_hasReadResult = false;
}

bool MemoryView::ReadMemory() {
	MEMORY_READ_REQUEST request{};
	unsigned long long address;

	if (!ParseHexU64(_addressText, address)) {
		_status = "Invalid address.";
		return false;
	}

	request.Pid = 0;
	request.Address = address;
	request.Size = _size;
	if (request.Size > sizeof(_readResult.Data)) {
		_status = "Read size must be 4096 bytes or less.";
		return false;
	}

	if (RemoteClient::IsConnected()) {
		if (!RemoteClient::MemoryRead(request, _readResult)) {
			_status = "Remote memory read failed.";
			return false;
		}
	}
	else if (!DriverHelper::MemoryRead(request, _readResult)) {
		_status = Utils::WideToUtf8(DriverHelper::GetLastErrorText());
		return false;
	}

	_hasReadRequest = true;
	_hasReadResult = true;
	_status = "Read completed.";
	LoggerView::AddLog(LoggerView::UserModeLog,
		"Read %lu bytes at 0x%016llX", _readResult.BytesRead, request.Address);
	return true;
}

bool MemoryView::WriteMemory() {
	MEMORY_WRITE_REQUEST request{};
	MEMORY_WRITE_RESULT result{};
	unsigned long long address;
	std::vector<unsigned char> bytes;

	if (!ParseHexU64(_addressText, address)) {
		_status = "Invalid address.";
		return false;
	}
	if (!ParseHexBytes(_writeHex, bytes)) {
		_status = "Hex input must contain full byte pairs.";
		return false;
	}
	if (bytes.size() > sizeof(request.Data)) {
		_status = "Write size must be 4096 bytes or less.";
		return false;
	}

	request.Pid = 0;
	request.Address = address;
	request.Size = (unsigned long)bytes.size();
	if (!bytes.empty())
		memcpy(request.Data, bytes.data(), bytes.size());

	if (RemoteClient::IsConnected()) {
		if (!RemoteClient::MemoryWrite(request, result)) {
			_status = "Remote memory write failed.";
			return false;
		}
	}
	else if (!DriverHelper::MemoryWrite(request, result)) {
		_status = Utils::WideToUtf8(DriverHelper::GetLastErrorText());
		return false;
	}

	_status = "Write completed.";
	LoggerView::AddLog(LoggerView::UserModeLog,
		"Wrote %lu bytes at 0x%016llX", result.BytesWritten, request.Address);
	return true;
}

void MemoryView::RefreshNow() {
	if (_hasReadRequest)
		ReadMemory();
	else
		ResetReadState();
}

void MemoryView::BuildHexDump() {
	unsigned long offset;

	if (!_hasReadResult) {
		TextDisabled("No memory data loaded.");
		return;
	}

	BeginChild("##MemoryHexDump", ImVec2(0.0f, 260.0f), true, ImGuiWindowFlags_HorizontalScrollbar);
	for (offset = 0; offset < _readResult.BytesRead; offset += 16) {
		char line[160];
		char* cursor;
		unsigned long index;

		cursor = line;
		cursor += sprintf_s(cursor, sizeof(line), "%08lX  ", offset);
		for (index = 0; index < 16; index++) {
			if (offset + index < _readResult.BytesRead)
				cursor += sprintf_s(cursor, sizeof(line) - (cursor - line), "%02X ", _readResult.Data[offset + index]);
			else
				cursor += sprintf_s(cursor, sizeof(line) - (cursor - line), "   ");
		}
		cursor += sprintf_s(cursor, sizeof(line) - (cursor - line), " ");
		for (index = 0; index < 16 && offset + index < _readResult.BytesRead; index++)
			*cursor++ = Printable(_readResult.Data[offset + index]);
		*cursor = '\0';
		Selectable(line, false);
	}
	EndChild();
}

void MemoryView::BuildWindow() {
	InputText("Address", _addressText, sizeof(_addressText), ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_AutoSelectAll);
	InputScalar("Size", ImGuiDataType_U32, &_size);
	if (_size > 4096)
		_size = 4096;

	if (Button("Read")) {
		ResetReadState();
		ReadMemory();
	}
	SameLine();
	if (Button("Write"))
		WriteMemory();

	if (!_status.empty())
		TextUnformatted(_status.c_str());

	InputTextMultiline("Hex Bytes", _writeHex, sizeof(_writeHex), ImVec2(-FLT_MIN, 110.0f));
	Separator();
	Text("Last Read: %lu bytes", _readResult.BytesRead);
	SameLine();
	TextDisabled("|");
	SameLine();
	Text("Address: 0x%016llX", _hasReadRequest ? _strtoui64(_addressText, nullptr, 16) : 0ull);
	BuildHexDump();
}
