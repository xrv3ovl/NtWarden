#pragma once

#include "KWinSys.h"

/* Forward declarations for new security-related IOCTL handlers */

NTSTATUS WinSysHandleQueryInstrumentationCb(PIRP Irp, PIO_STACK_LOCATION stack);
NTSTATUS WinSysHandleSnapshotCallbacks(PIRP Irp, PIO_STACK_LOCATION stack);
NTSTATUS WinSysHandleDiffCallbacks(PIRP Irp, PIO_STACK_LOCATION stack);
NTSTATUS WinSysHandleEnumApc(PIRP Irp, PIO_STACK_LOCATION stack);
NTSTATUS WinSysHandleQueryDseStatus(PIRP Irp, PIO_STACK_LOCATION stack);
NTSTATUS WinSysHandleQueryKernelIntegrity(PIRP Irp, PIO_STACK_LOCATION stack);
NTSTATUS WinSysHandleQueryPatchGuardTimers(PIRP Irp, PIO_STACK_LOCATION stack);
