#pragma once

#include "KernelRuntime.h"
#include "KWinSysPublic.h"

NTSTATUS WinSysHandleQueryKernelLogs(PIRP Irp, PIO_STACK_LOCATION stack);
