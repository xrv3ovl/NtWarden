#pragma once

#include <iphlpapi.h>
#include <string>
#include "Keys.h"
//#include <algorithm>

namespace WinSys {
	class ActiveConnectionTracker {
	public:
		int EnumConnections();
		void Reset();

		void SetTrackingFlags(ConnectionType type);
		ConnectionType GetTrackingFlags() const;

		using ConnectionMap = std::unordered_map<Connection, std::shared_ptr<Connection>>;
		using ConnectionVec = std::vector<std::shared_ptr<Connection>>;

		const ConnectionVec& GetConnections() const;
		const ConnectionVec& GetNewConnections() const;
		const ConnectionVec& GetCloseConnections() const;

		ConnectionType _trackedConnections{ ConnectionType::All };
		ConnectionVec _connections;
		ConnectionVec _newConnections;
		ConnectionVec _closedConnections;
		ConnectionMap _connectionMap;
	};
}


