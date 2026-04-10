#pragma once

#include "ViewBase.h"

class IPCView : public ViewBase {
public:
	IPCView();

	void BuildWindow();
	void RefreshNow();

private:
	struct RpcEndpointInfo {
		std::wstring InterfaceId;
		unsigned short MajorVersion{ 0 };
		unsigned short MinorVersion{ 0 };
		std::wstring Binding;
		std::wstring Annotation;
	};

	struct NamedPipeInfo {
		std::wstring Name;
	};

	void Refresh();
	void BuildToolBar();
	void BuildRpcTable();
	void BuildNamedPipesTable();

	std::vector<RpcEndpointInfo> _rpcEndpoints;
	std::vector<NamedPipeInfo> _namedPipes;
};
