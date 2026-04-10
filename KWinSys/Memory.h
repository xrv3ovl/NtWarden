#pragma once

#include "KernelRuntime.h"
#include "KWinSysPublic.h"

NTSTATUS WinSysHandleMemoryRead(PIRP Irp, PIO_STACK_LOCATION stack);
NTSTATUS WinSysHandleMemoryWrite(PIRP Irp, PIO_STACK_LOCATION stack);
