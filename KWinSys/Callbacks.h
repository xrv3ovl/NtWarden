#pragma once

#include "KernelRuntime.h"
#include "KWinSysPublic.h"

NTSTATUS WinSysHandleListCallbacks(PIRP Irp, PIO_STACK_LOCATION stack);
