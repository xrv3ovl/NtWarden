#pragma once

#include "KernelRuntime.h"
#include "KWinSysPublic.h"

NTSTATUS WinSysHandleEnumWfpFilters(PIRP Irp, PIO_STACK_LOCATION stack);
NTSTATUS WinSysHandleEnumWfpCallouts(PIRP Irp, PIO_STACK_LOCATION stack);
