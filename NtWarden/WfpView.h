#pragma once
#include "../KWinSys/KWinSysPublic.h"
#include <vector>
#include <future>

class WfpView {
public:
    void BuildWindow();
    void RefreshNow();
private:
    void RefreshFilters();
    void RefreshCallouts();
    void BuildFiltersTab();
    void BuildCalloutsTab();

    std::vector<WFP_FILTER_ENTRY> _filters;
    std::vector<WFP_CALLOUT_ENTRY> _callouts;
    bool _filtersLoaded{ false };
    bool _calloutsLoaded{ false };
    bool _filtersLoading{ false };
    bool _calloutsLoading{ false };
    std::future<std::vector<WFP_FILTER_ENTRY>> _filtersFuture;
    std::future<std::vector<WFP_CALLOUT_ENTRY>> _calloutsFuture;
};
