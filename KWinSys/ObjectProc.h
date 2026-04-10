#pragma once

#include "KernelRuntime.h"
#include "KWinSysPublic.h"

NTSTATUS WinSysHandleSetObjectProcOffsets(PIRP Irp, PIO_STACK_LOCATION stack);
NTSTATUS WinSysHandleQueryObjectProcs(PIRP Irp, PIO_STACK_LOCATION stack);
