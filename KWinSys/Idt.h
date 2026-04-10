#pragma once

#include "KernelRuntime.h"
#include "KWinSysPublic.h"

NTSTATUS WinSysHandleQueryIdt(PIRP Irp, PIO_STACK_LOCATION stack);
