#pragma once

#include "../KWinSys/KWinSysPublic.h"
#include <string>

class MemoryView {
public:
	void BuildWindow();
	void RefreshNow();

private:
	bool ReadMemory();
	bool WriteMemory();
	void BuildHexDump();
	void ResetReadState();

	unsigned long _size{ 64 };
	char _addressText[32]{ "FFFFF80000000000" };
	char _writeHex[12288]{};
	MEMORY_READ_RESULT _readResult{};
	bool _hasReadResult{ false };
	bool _hasReadRequest{ false };
	std::string _status;
};
