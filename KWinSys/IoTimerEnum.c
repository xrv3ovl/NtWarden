#include "pch.h"
#include "KWinSysPublic.h"
#include "KernelRuntime.h"

NTSTATUS WinSysHandleEnumIoTimers(PIRP Irp, PIO_STACK_LOCATION stack) {
	IO_TIMER_QUERY* query;
	IO_TIMER_RESULT* resultHeader;
	IO_TIMER_ENTRY* entries;
	ULONG outputSize, maxEntries, entryCount = 0;
	ULONG_PTR listHead;

	if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(IO_TIMER_QUERY))
		return CompleteRequest(Irp, STATUS_BUFFER_TOO_SMALL, 0);

	outputSize = stack->Parameters.DeviceIoControl.OutputBufferLength;
	if (outputSize < sizeof(IO_TIMER_RESULT) + sizeof(IO_TIMER_ENTRY))
		return CompleteRequest(Irp, STATUS_BUFFER_TOO_SMALL, 0);

	query = (IO_TIMER_QUERY*)Irp->AssociatedIrp.SystemBuffer;
	if (!query->Valid || query->IopTimerQueueHead == 0)
		return CompleteRequest(Irp, STATUS_DEVICE_NOT_READY, 0);

	maxEntries = (outputSize - sizeof(IO_TIMER_RESULT)) / sizeof(IO_TIMER_ENTRY);
	if (maxEntries > MAX_IO_TIMERS) maxEntries = MAX_IO_TIMERS;

	resultHeader = (IO_TIMER_RESULT*)Irp->AssociatedIrp.SystemBuffer;
	entries = (IO_TIMER_ENTRY*)((PUCHAR)resultHeader + sizeof(IO_TIMER_RESULT));
	RtlZeroMemory(resultHeader, sizeof(IO_TIMER_RESULT));

	listHead = (ULONG_PTR)query->IopTimerQueueHead;

	__try {
		PLIST_ENTRY head = (PLIST_ENTRY)listHead;
		PLIST_ENTRY entry = head->Flink;

		while (entry != head && entryCount < maxEntries) {
			/* IO_TIMER layout: the linked list entry is at TimerListOffset from the IO_TIMER base.
			   DeviceObject at DeviceObjectOffset, TimerRoutine at TimerRoutineOffset. */
			ULONG_PTR timerBase = (ULONG_PTR)entry - query->TimerListOffset;
			PDEVICE_OBJECT devObj;
			PVOID routine;

			devObj = *(PDEVICE_OBJECT*)(timerBase + query->DeviceObjectOffset);
			routine = *(PVOID*)(timerBase + query->TimerRoutineOffset);

			entries[entryCount].DeviceObject = (ULONG_PTR)devObj;
			entries[entryCount].TimerRoutine = (ULONG_PTR)routine;
			entries[entryCount].DriverObject = 0;
			entries[entryCount].DriverName[0] = '\0';

			if (devObj && MmIsAddressValid(devObj)) {
				PDRIVER_OBJECT drvObj = devObj->DriverObject;
				entries[entryCount].DriverObject = (ULONG_PTR)drvObj;
				if (drvObj && MmIsAddressValid(drvObj) && drvObj->DriverName.Buffer) {
					ANSI_STRING ansi;
					NTSTATUS convStatus;
					ansi.Buffer = entries[entryCount].DriverName;
					ansi.MaximumLength = 127;
					convStatus = RtlUnicodeStringToAnsiString(&ansi, &drvObj->DriverName, FALSE);
					if (NT_SUCCESS(convStatus))
						entries[entryCount].DriverName[ansi.Length] = '\0';
				}
			}

			entryCount++;
			entry = entry->Flink;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		/* Return what we have so far */
	}

	resultHeader->Count = entryCount;
	return CompleteRequest(Irp, STATUS_SUCCESS,
		sizeof(IO_TIMER_RESULT) + entryCount * sizeof(IO_TIMER_ENTRY));
}
