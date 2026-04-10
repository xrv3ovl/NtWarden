#include "pch.h"
#include "KernelLog.h"

#define WINSYS_LOG_RING_SIZE 512

typedef struct _WINSYS_LOG_SLOT {
	ULONG Sequence;
	CHAR Text[256];
} WINSYS_LOG_SLOT, * PWINSYS_LOG_SLOT;

static KSPIN_LOCK g_WinSysLogLock;
static ULONG g_WinSysLogNextSequence = 1;
static ULONG g_WinSysLogCount = 0;
static WINSYS_LOG_SLOT g_WinSysLogRing[WINSYS_LOG_RING_SIZE];
static BOOLEAN g_WinSysLogInitialized = FALSE;

static VOID WinSysTrimLogLine(_Inout_updates_z_(256) PCHAR text) {
	SIZE_T length;

	if (text == NULL)
		return;

	if (!NT_SUCCESS(RtlStringCbLengthA(text, 256, &length)))
		return;
	while (length > 0 && (text[length - 1] == '\n' || text[length - 1] == '\r')) {
		text[length - 1] = '\0';
		length--;
	}
}

VOID WinSysInitializeKernelLog() {
	KIRQL oldIrql;

	KeInitializeSpinLock(&g_WinSysLogLock);
	KeAcquireSpinLock(&g_WinSysLogLock, &oldIrql);
	RtlZeroMemory(g_WinSysLogRing, sizeof(g_WinSysLogRing));
	g_WinSysLogNextSequence = 1;
	g_WinSysLogCount = 0;
	g_WinSysLogInitialized = TRUE;
	KeReleaseSpinLock(&g_WinSysLogLock, oldIrql);
}

VOID WinSysShutdownKernelLog() {
	if (!g_WinSysLogInitialized)
		return;

	KIRQL oldIrql;

	KeAcquireSpinLock(&g_WinSysLogLock, &oldIrql);
	RtlZeroMemory(g_WinSysLogRing, sizeof(g_WinSysLogRing));
	g_WinSysLogNextSequence = 1;
	g_WinSysLogCount = 0;
	g_WinSysLogInitialized = FALSE;
	KeReleaseSpinLock(&g_WinSysLogLock, oldIrql);
}

VOID WinSysTrace(PCSTR Format, ...) {
	CHAR text[256];
	NTSTATUS status;
	ULONG sequence;
	ULONG slotIndex;
	KIRQL oldIrql;
	va_list args;

	if (Format == NULL)
		return;

	va_start(args, Format);
	status = RtlStringCbVPrintfA(text, sizeof(text), Format, args);
	va_end(args);

	if (!NT_SUCCESS(status))
		RtlStringCbCopyA(text, sizeof(text), DRIVER_PREFIX "<trace format error>");

	WinSysTrimLogLine(text);

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "%s\n", text);

	if (!g_WinSysLogInitialized)
		return;

	KeAcquireSpinLock(&g_WinSysLogLock, &oldIrql);
	sequence = g_WinSysLogNextSequence++;
	slotIndex = (sequence - 1) % WINSYS_LOG_RING_SIZE;
	g_WinSysLogRing[slotIndex].Sequence = sequence;
	RtlZeroMemory(g_WinSysLogRing[slotIndex].Text, sizeof(g_WinSysLogRing[slotIndex].Text));
	RtlStringCbCopyA(g_WinSysLogRing[slotIndex].Text, sizeof(g_WinSysLogRing[slotIndex].Text), text);
	if (g_WinSysLogCount < WINSYS_LOG_RING_SIZE)
		g_WinSysLogCount++;
	KeReleaseSpinLock(&g_WinSysLogLock, oldIrql);
}

NTSTATUS WinSysHandleQueryKernelLogs(PIRP Irp, PIO_STACK_LOCATION stack) {
	KERNEL_LOG_QUERY* request;
	KERNEL_LOG_RESULT* result;
	KERNEL_LOG_ENTRY* entries;
	ULONG requestedSequence;
	ULONG oldestSequence;
	ULONG nextSequence;
	ULONG sequence;
	ULONG availableEntries;
	ULONG maxEntries;
	ULONG count;
	ULONG i;
	KIRQL oldIrql;

	if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(KERNEL_LOG_QUERY) ||
		stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(KERNEL_LOG_RESULT))
		return CompleteRequest(Irp, STATUS_BUFFER_TOO_SMALL, 0);

	request = (KERNEL_LOG_QUERY*)Irp->AssociatedIrp.SystemBuffer;
	result = (KERNEL_LOG_RESULT*)Irp->AssociatedIrp.SystemBuffer;
	RtlZeroMemory(result, stack->Parameters.DeviceIoControl.OutputBufferLength);

	if (!g_WinSysLogInitialized)
		return CompleteRequest(Irp, STATUS_DEVICE_NOT_READY, 0);

	maxEntries = (stack->Parameters.DeviceIoControl.OutputBufferLength - sizeof(KERNEL_LOG_RESULT)) / sizeof(KERNEL_LOG_ENTRY);
	if (maxEntries > MAX_KERNEL_LOG_ENTRIES)
		maxEntries = MAX_KERNEL_LOG_ENTRIES;

	entries = (KERNEL_LOG_ENTRY*)((PUCHAR)result + sizeof(KERNEL_LOG_RESULT));
	requestedSequence = request->StartSequence;

	KeAcquireSpinLock(&g_WinSysLogLock, &oldIrql);

	nextSequence = g_WinSysLogNextSequence;
	oldestSequence = g_WinSysLogCount == 0 ? nextSequence : (nextSequence - g_WinSysLogCount);
	if (requestedSequence == 0 || requestedSequence < oldestSequence)
		requestedSequence = oldestSequence;
	if (requestedSequence > nextSequence)
		requestedSequence = nextSequence;

	availableEntries = nextSequence - requestedSequence;
	count = availableEntries < maxEntries ? availableEntries : maxEntries;

	for (i = 0; i < count; i++) {
		ULONG slotIndex;

		sequence = requestedSequence + i;
		slotIndex = (sequence - 1) % WINSYS_LOG_RING_SIZE;
		entries[i].Sequence = g_WinSysLogRing[slotIndex].Sequence;
		RtlZeroMemory(entries[i].Text, sizeof(entries[i].Text));
		RtlStringCbCopyA(entries[i].Text, sizeof(entries[i].Text), g_WinSysLogRing[slotIndex].Text);
	}

	result->Count = count;
	result->NextSequence = requestedSequence + count;

	KeReleaseSpinLock(&g_WinSysLogLock, oldIrql);

	return CompleteRequest(Irp, STATUS_SUCCESS, sizeof(KERNEL_LOG_RESULT) + count * sizeof(KERNEL_LOG_ENTRY));
}
