#pragma once

#include "KernelRuntime.h"
#include "KWinSysPublic.h"

NTSTATUS WinSysHandleEnumIoTimers(PIRP Irp, PIO_STACK_LOCATION stack);
