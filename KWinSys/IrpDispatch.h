#pragma once

#include "KernelRuntime.h"
#include "KWinSysPublic.h"

NTSTATUS WinSysHandleQueryIrpDispatch(PIRP Irp, PIO_STACK_LOCATION stack);
