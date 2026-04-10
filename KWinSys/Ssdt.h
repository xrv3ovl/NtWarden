#pragma once

#include "KernelRuntime.h"
#include "KWinSysPublic.h"

NTSTATUS WinSysHandleListSsdt(PIRP Irp, PIO_STACK_LOCATION stack);
