#pragma once
#include "../KWinSys/KWinSysPublic.h"
#include <string>
#include <vector>
#include <future>

class IrpDispatchView {
public:
    void BuildWindow();
    void RefreshNow();
private:
    void QueryDriver(const wchar_t* driverName);

    struct IrpEntry {
        int Index;
        std::string FunctionName;
        unsigned long long Address;
        std::string Owner;
    };

    std::vector<IrpEntry> _entries;
    char _driverNameBuf[256]{ "\\Driver\\Tcpip" };
    std::string _selectedDriverDisplay;
    bool _queried{ false };
    bool _loading{ false };
    std::future<std::vector<IrpEntry>> _queryFuture;
};
