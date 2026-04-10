#include "pch.h"
#include "KWinSysPublic.h"
#include "KernelRuntime.h"

#pragma pack(push, 1)
typedef struct _KIDTR {
	USHORT Limit;
	ULONG64 Base;
} KIDTR, *PKIDTR;

/* x64 IDT gate descriptor (16 bytes) */
typedef struct _KIDTENTRY64 {
	USHORT OffsetLow;
	USHORT Selector;
	UCHAR IstIndex : 3;
	UCHAR Reserved0 : 5;
	UCHAR Type : 4;
	UCHAR Zero : 1;
	UCHAR Dpl : 2;
	UCHAR Present : 1;
	USHORT OffsetMiddle;
	ULONG OffsetHigh;
	ULONG Reserved1;
} KIDTENTRY64, *PKIDTENTRY64;
#pragma pack(pop)

NTSTATUS WinSysHandleQueryIdt(PIRP Irp, PIO_STACK_LOCATION stack) {
	IDT_INFO* info;
	KIDTR idtr;
	ULONG count;

	if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(IDT_INFO))
		return CompleteRequest(Irp, STATUS_BUFFER_TOO_SMALL, 0);

	info = (IDT_INFO*)Irp->AssociatedIrp.SystemBuffer;
	RtlZeroMemory(info, sizeof(IDT_INFO));

	RtlZeroMemory(&idtr, sizeof(idtr));
	__sidt(&idtr);

	if (idtr.Base == 0 || idtr.Limit < sizeof(KIDTENTRY64) - 1)
		return CompleteRequest(Irp, STATUS_UNSUCCESSFUL, 0);

	info->Limit = idtr.Limit;
	info->Base = idtr.Base;
	count = (ULONG)((idtr.Limit + 1) / sizeof(KIDTENTRY64));
	if (count > 256) count = 256;
	info->EntryCount = count;

	__try {
		PKIDTENTRY64 entries = (PKIDTENTRY64)idtr.Base;
		ULONG i;
		for (i = 0; i < count; i++) {
			info->Entries[i].IsrAddress =
				((ULONG64)entries[i].OffsetHigh << 32) |
				((ULONG64)entries[i].OffsetMiddle << 16) |
				(ULONG64)entries[i].OffsetLow;
			info->Entries[i].Segment = entries[i].Selector;
			info->Entries[i].IST = entries[i].IstIndex;
			info->Entries[i].Type = entries[i].Type;
			info->Entries[i].DPL = entries[i].Dpl;
			info->Entries[i].Present = entries[i].Present;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return CompleteRequest(Irp, GetExceptionCode(), 0);
	}

	return CompleteRequest(Irp, STATUS_SUCCESS, sizeof(IDT_INFO));
}
