#include "pch.h"
#include "KWinSysPublic.h"
#include "KernelRuntime.h"

#pragma pack(push, 1)
typedef struct _KGDTR {
	USHORT Limit;
	ULONG64 Base;
} KGDTR, *PKGDTR;
#pragma pack(pop)

NTSTATUS WinSysHandleQueryGdt(PIRP Irp, PIO_STACK_LOCATION stack) {
	GDT_INFO* info;
	KGDTR gdtr;
	ULONG count;

	if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(GDT_INFO))
		return CompleteRequest(Irp, STATUS_BUFFER_TOO_SMALL, 0);

	info = (GDT_INFO*)Irp->AssociatedIrp.SystemBuffer;
	RtlZeroMemory(info, sizeof(GDT_INFO));

	RtlZeroMemory(&gdtr, sizeof(gdtr));
	_sgdt(&gdtr);

	if (gdtr.Base == 0 || gdtr.Limit < sizeof(ULONGLONG) - 1)
		return CompleteRequest(Irp, STATUS_UNSUCCESSFUL, 0);

	info->Limit = gdtr.Limit;
	info->Base = gdtr.Base;
	count = (ULONG)((gdtr.Limit + 1) / sizeof(ULONGLONG));
	info->EntryCount = count < 256 ? count : 256;

	__try {
		RtlCopyMemory(info->Entries, (void*)gdtr.Base, info->EntryCount * sizeof(ULONGLONG));
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return CompleteRequest(Irp, GetExceptionCode(), 0);
	}

	return CompleteRequest(Irp, STATUS_SUCCESS, sizeof(GDT_INFO));
}
