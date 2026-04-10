#pragma once

#include "StructureModel.h"

#include <vector>

class StructureProvider {
public:
	virtual ~StructureProvider() = default;
	virtual std::vector<StructureDefinition> Load(const WindowsBuildInfo& buildInfo) = 0;
};

class BundledStructureProvider : public StructureProvider {
public:
	std::vector<StructureDefinition> Load(const WindowsBuildInfo& buildInfo) override;
};
