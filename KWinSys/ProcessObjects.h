#pragma once

#include "KWinSys.h"

NTSTATUS WinSysHandleEnumProcessObjects(PIRP Irp, PIO_STACK_LOCATION stack);
NTSTATUS WinSysHandleSetEprocessOffsets(PIRP Irp, PIO_STACK_LOCATION stack);
NTSTATUS WinSysHandleCrossCheckProcesses(PIRP Irp, PIO_STACK_LOCATION stack);
