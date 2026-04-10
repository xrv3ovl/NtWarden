#pragma once

#include "KernelRuntime.h"
#include "KWinSysPublic.h"

NTSTATUS WinSysHandleListModules(PIRP Irp, PIO_STACK_LOCATION stack);
NTSTATUS WinSysHandleCreateModuleSnapshot(PIRP Irp, PIO_STACK_LOCATION stack);
NTSTATUS WinSysHandleQueryModulePage(PIRP Irp, PIO_STACK_LOCATION stack);
NTSTATUS WinSysHandleReleaseModuleSnapshot(PIRP Irp, PIO_STACK_LOCATION stack);
