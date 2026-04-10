#pragma once

#include "ViewBase.h"

class KernelMemoryView : public ViewBase {
public:
	KernelMemoryView();
	void BuildWindow();
	void Refresh();

	struct BigPoolRow {
		ULONG64 VirtualAddress;
		ULONG64 SizeInBytes;
		std::string Tag;
		bool NonPaged;
		bool Executable;
	};

	struct PoolTagRow {
		std::string Tag;
		ULONG PagedAllocs;
		ULONG PagedFrees;
		ULONG64 PagedUsed;
		ULONG NonPagedAllocs;
		ULONG NonPagedFrees;
		ULONG64 NonPagedUsed;
	};

private:
	void BuildToolBar();
	void BuildSummary();
	void BuildBigPoolTable();
	void BuildPoolTagTable();

	std::vector<BigPoolRow> _bigPool;
	std::vector<PoolTagRow> _poolTags;
};
