#include "pch.h"
#include <wdm.h>
#include <string.h>
#include "ProcessObjects.h"
#include "KernelRuntime.h"
#include "KWinSysPublic.h"

typedef PUCHAR(NTAPI* PSGETPROCESSIMAGEFILENAME)(PEPROCESS Process);
typedef LONGLONG(NTAPI* PSGETPROCESSCREATETIMEQUADPART)(PEPROCESS Process);
typedef PVOID(NTAPI* PSGETPROCESSWOW64PROCESS)(PEPROCESS Process);
typedef BOOLEAN(NTAPI* PSISPROTECTEDPROCESS)(PEPROCESS Process);
typedef BOOLEAN(NTAPI* PSISPROTECTEDPROCESSLIGHT)(PEPROCESS Process);

typedef struct _LOCAL_SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER Reserved[3];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	LONG BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
} LOCAL_SYSTEM_PROCESS_INFORMATION, *PLOCAL_SYSTEM_PROCESS_INFORMATION;

/* Stored PDB-resolved offsets (set via IOCTL from user-mode) */
static EPROCESS_OFFSETS g_EprocessOffsets = { 0 };
static const ULONG INVALID_OFFSET = (ULONG)-1;

/* Safe kernel memory read helpers */
static BOOLEAN SafeReadUchar(PEPROCESS eprocess, ULONG offset, PUCHAR result) {
	__try {
		PUCHAR addr = (PUCHAR)eprocess + offset;
		if (!MmIsAddressValid(addr))
			return FALSE;
		*result = *addr;
		return TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}
}

static BOOLEAN SafeReadUlong(PEPROCESS eprocess, ULONG offset, PULONG result) {
	__try {
		PUCHAR addr = (PUCHAR)eprocess + offset;
		if (!MmIsAddressValid(addr))
			return FALSE;
		*result = *(PULONG)addr;
		return TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}
}

static BOOLEAN SafeReadPointer(PEPROCESS eprocess, ULONG offset, PULONG_PTR result) {
	__try {
		PUCHAR addr = (PUCHAR)eprocess + offset;
		if (!MmIsAddressValid(addr))
			return FALSE;
		*result = *(PULONG_PTR)addr;
		return TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}
}

static BOOLEAN SafeReadListEntry(PVOID addr, PLIST_ENTRY result) {
	__try {
		if (!MmIsAddressValid(addr))
			return FALSE;
		if (!MmIsAddressValid((PUCHAR)addr + sizeof(PVOID)))
			return FALSE;
		result->Flink = ((PLIST_ENTRY)addr)->Flink;
		result->Blink = ((PLIST_ENTRY)addr)->Blink;
		return TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}
}

NTSTATUS WinSysHandleSetEprocessOffsets(PIRP Irp, PIO_STACK_LOCATION stack) {
	if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(EPROCESS_OFFSETS))
		return CompleteRequest(Irp, STATUS_BUFFER_TOO_SMALL, 0);

	EPROCESS_OFFSETS* input = (EPROCESS_OFFSETS*)Irp->AssociatedIrp.SystemBuffer;
	g_EprocessOffsets = *input;

	KdPrint((DRIVER_PREFIX "EPROCESS offsets set: Protection=0x%lx Token=0x%lx Peb=0x%lx DirBase=0x%lx Flags=0x%lx\n",
		g_EprocessOffsets.ProtectionOffset,
		g_EprocessOffsets.TokenOffset,
		g_EprocessOffsets.PebOffset,
		g_EprocessOffsets.DirectoryTableBaseOffset,
		g_EprocessOffsets.FlagsOffset));

	return CompleteRequest(Irp, STATUS_SUCCESS, 0);
}

static void FillPdbFields(PEPROCESS eprocess, KERNEL_PROCESS_ENTRY* entry) {
	UCHAR protByte = 0;
	ULONG_PTR tokenRef = 0;
	ULONG_PTR pebAddr = 0;
	ULONG_PTR dirBase = 0;
	ULONG_PTR objTable = 0;

	if (g_EprocessOffsets.ProtectionOffset != INVALID_OFFSET &&
		SafeReadUchar(eprocess, g_EprocessOffsets.ProtectionOffset, &protByte)) {
		entry->Protection = protByte;
		entry->ProtectionType = protByte & 0x07;       /* bits 0-2 */
		entry->ProtectionSigner = (protByte >> 4) & 0x0F; /* bits 4-7 */
	}

	if (g_EprocessOffsets.TokenOffset != INVALID_OFFSET &&
		SafeReadPointer(eprocess, g_EprocessOffsets.TokenOffset, &tokenRef)) {
		/* EX_FAST_REF: mask out the low 4 bits (ref count) on x64 */
		entry->TokenAddress = (unsigned long long)(tokenRef & ~(ULONG_PTR)0xF);
	}

	if (g_EprocessOffsets.PebOffset != INVALID_OFFSET &&
		SafeReadPointer(eprocess, g_EprocessOffsets.PebOffset, &pebAddr)) {
		entry->PebAddress = (unsigned long long)pebAddr;
	}

	if (g_EprocessOffsets.DirectoryTableBaseOffset != INVALID_OFFSET &&
		SafeReadPointer(eprocess, g_EprocessOffsets.DirectoryTableBaseOffset, &dirBase)) {
		entry->DirectoryTableBase = (unsigned long long)dirBase;
	}

	if (g_EprocessOffsets.ObjectTableOffset != INVALID_OFFSET &&
		SafeReadPointer(eprocess, g_EprocessOffsets.ObjectTableOffset, &objTable)) {
		entry->ObjectTableAddress = (unsigned long long)objTable;
	}

	if (g_EprocessOffsets.FlagsOffset != INVALID_OFFSET)
		SafeReadUlong(eprocess, g_EprocessOffsets.FlagsOffset, &entry->Flags);

	if (g_EprocessOffsets.Flags2Offset != INVALID_OFFSET)
		SafeReadUlong(eprocess, g_EprocessOffsets.Flags2Offset, &entry->Flags2);

	if (g_EprocessOffsets.SignatureLevelOffset != INVALID_OFFSET)
		SafeReadUchar(eprocess, g_EprocessOffsets.SignatureLevelOffset, &entry->SignatureLevel);

	if (g_EprocessOffsets.SectionSignatureLevelOffset != INVALID_OFFSET)
		SafeReadUchar(eprocess, g_EprocessOffsets.SectionSignatureLevelOffset, &entry->SectionSignatureLevel);

	if (g_EprocessOffsets.MitigationFlagsOffset != INVALID_OFFSET)
		SafeReadUlong(eprocess, g_EprocessOffsets.MitigationFlagsOffset, &entry->MitigationFlags);

	if (g_EprocessOffsets.MitigationFlags2Offset != INVALID_OFFSET)
		SafeReadUlong(eprocess, g_EprocessOffsets.MitigationFlags2Offset, &entry->MitigationFlags2);
}

NTSTATUS WinSysHandleEnumProcessObjects(PIRP Irp, PIO_STACK_LOCATION stack) {
	ULONG requiredSize = sizeof(ULONG) + sizeof(KERNEL_PROCESS_ENTRY) * MAX_KERNEL_PROCESSES;
	NTSTATUS status;
	PVOID sysInfoBuffer = NULL;
	ULONG sysInfoSize = 0;
	ULONG returnLength = 0;
	PLOCAL_SYSTEM_PROCESS_INFORMATION procInfo;
	KERNEL_PROCESS_ENTRY* outEntries;
	ULONG* outCount;
	ULONG count = 0;

	UNICODE_STRING fnName;
	static PSGETPROCESSIMAGEFILENAME pPsGetProcessImageFileName = NULL;
	static PSGETPROCESSCREATETIMEQUADPART pPsGetProcessCreateTimeQuadPart = NULL;
	static PSGETPROCESSWOW64PROCESS pPsGetProcessWow64Process = NULL;
	static PSISPROTECTEDPROCESS pPsIsProtectedProcess = NULL;
	static PSISPROTECTEDPROCESSLIGHT pPsIsProtectedProcessLight = NULL;
	static BOOLEAN resolvedOnce = FALSE;

	if (stack->Parameters.DeviceIoControl.OutputBufferLength < requiredSize)
		return CompleteRequest(Irp, STATUS_BUFFER_TOO_SMALL, 0);

	outCount = (ULONG*)Irp->AssociatedIrp.SystemBuffer;
	outEntries = (KERNEL_PROCESS_ENTRY*)((PUCHAR)outCount + sizeof(ULONG));
	RtlZeroMemory(outCount, requiredSize);

	if (!resolvedOnce) {
		RtlInitUnicodeString(&fnName, L"PsGetProcessImageFileName");
		pPsGetProcessImageFileName = (PSGETPROCESSIMAGEFILENAME)MmGetSystemRoutineAddress(&fnName);

		RtlInitUnicodeString(&fnName, L"PsGetProcessCreateTimeQuadPart");
		pPsGetProcessCreateTimeQuadPart = (PSGETPROCESSCREATETIMEQUADPART)MmGetSystemRoutineAddress(&fnName);

		RtlInitUnicodeString(&fnName, L"PsGetProcessWow64Process");
		pPsGetProcessWow64Process = (PSGETPROCESSWOW64PROCESS)MmGetSystemRoutineAddress(&fnName);

		RtlInitUnicodeString(&fnName, L"PsIsProtectedProcess");
		pPsIsProtectedProcess = (PSISPROTECTEDPROCESS)MmGetSystemRoutineAddress(&fnName);

		RtlInitUnicodeString(&fnName, L"PsIsProtectedProcessLight");
		pPsIsProtectedProcessLight = (PSISPROTECTEDPROCESSLIGHT)MmGetSystemRoutineAddress(&fnName);

		resolvedOnce = TRUE;
	}

	status = LOLZwQuerySystemInformation(SystemProcessInformation, &sysInfoSize, 0, &sysInfoSize);
	if (status != STATUS_INFO_LENGTH_MISMATCH && !NT_SUCCESS(status))
		return CompleteRequest(Irp, status, 0);

	sysInfoSize *= 2;
	sysInfoBuffer = ExAllocatePoolWithTag(NonPagedPool, sysInfoSize, 'orPw');
	if (!sysInfoBuffer)
		return CompleteRequest(Irp, STATUS_INSUFFICIENT_RESOURCES, 0);

	status = LOLZwQuerySystemInformation(SystemProcessInformation, sysInfoBuffer, sysInfoSize, &returnLength);
	if (!NT_SUCCESS(status)) {
		ExFreePool(sysInfoBuffer);
		return CompleteRequest(Irp, status, 0);
	}

	procInfo = (PLOCAL_SYSTEM_PROCESS_INFORMATION)sysInfoBuffer;
	for (;;) {
		if (count >= MAX_KERNEL_PROCESSES)
			break;

		{
			PEPROCESS eprocess = NULL;
			HANDLE pid = procInfo->UniqueProcessId;
			KERNEL_PROCESS_ENTRY* entry = &outEntries[count];

			entry->ProcessId = (ULONG)(ULONG_PTR)pid;
			entry->ParentProcessId = (ULONG)(ULONG_PTR)procInfo->InheritedFromUniqueProcessId;
			entry->SessionId = procInfo->SessionId;
			entry->HandleCount = procInfo->HandleCount;
			entry->ThreadCount = procInfo->NumberOfThreads;
			entry->CreateTime = procInfo->CreateTime.QuadPart;

			status = PsLookupProcessByProcessId(pid, &eprocess);
			if (NT_SUCCESS(status)) {
				entry->EprocessAddress = (unsigned long long)(ULONG_PTR)eprocess;

				if (pPsGetProcessImageFileName) {
					PUCHAR imageName = pPsGetProcessImageFileName(eprocess);
					if (imageName) {
						strncpy(entry->ImageName, (const char*)imageName, 15);
						entry->ImageName[15] = '\0';
					}
				}

				if (pPsGetProcessCreateTimeQuadPart)
					entry->CreateTime = pPsGetProcessCreateTimeQuadPart(eprocess);

				if (pPsGetProcessWow64Process)
					entry->IsWow64 = pPsGetProcessWow64Process(eprocess) != NULL ? 1 : 0;

				if (pPsIsProtectedProcess)
					entry->IsProtected = pPsIsProtectedProcess(eprocess) ? 1 : 0;

				if (pPsIsProtectedProcessLight)
					entry->IsProtectedLight = pPsIsProtectedProcessLight(eprocess) ? 1 : 0;

				/* Read PDB-resolved fields if offsets are available */
				if (g_EprocessOffsets.Valid)
					FillPdbFields(eprocess, entry);

				ObDereferenceObject(eprocess);
			}
			else {
				if (entry->ProcessId == 0)
					strncpy(entry->ImageName, "System Idle", 15);
			}

			count++;
		}

		if (procInfo->NextEntryOffset == 0)
			break;
		procInfo = (PLOCAL_SYSTEM_PROCESS_INFORMATION)((PUCHAR)procInfo + procInfo->NextEntryOffset);
	}

	ExFreePool(sysInfoBuffer);
	*outCount = count;

	return CompleteRequest(Irp, STATUS_SUCCESS, sizeof(ULONG) + sizeof(KERNEL_PROCESS_ENTRY) * count);
}

/*
 * DKOM Cross-Check: Walk ActiveProcessLinks and brute-force PspCidTable,
 * then compare to detect unlinked (hidden) processes.
 */
NTSTATUS WinSysHandleCrossCheckProcesses(PIRP Irp, PIO_STACK_LOCATION stack) {
	ULONG requiredSize = sizeof(CROSS_CHECK_RESULT) + sizeof(CROSS_CHECK_PROCESS_ENTRY) * MAX_CROSS_CHECK_PROCESSES;
	NTSTATUS status;

	static PSGETPROCESSIMAGEFILENAME pPsGetProcessImageFileName = NULL;
	static BOOLEAN resolvedCrossCheck = FALSE;

	if (stack->Parameters.DeviceIoControl.OutputBufferLength < requiredSize)
		return CompleteRequest(Irp, STATUS_BUFFER_TOO_SMALL, 0);

	if (!g_EprocessOffsets.Valid ||
		g_EprocessOffsets.ActiveProcessLinksOffset == INVALID_OFFSET ||
		g_EprocessOffsets.UniqueProcessIdOffset == INVALID_OFFSET) {
		return CompleteRequest(Irp, STATUS_DEVICE_NOT_READY, 0);
	}

	if (!resolvedCrossCheck) {
		UNICODE_STRING fnName;
		RtlInitUnicodeString(&fnName, L"PsGetProcessImageFileName");
		pPsGetProcessImageFileName = (PSGETPROCESSIMAGEFILENAME)MmGetSystemRoutineAddress(&fnName);
		resolvedCrossCheck = TRUE;
	}

	CROSS_CHECK_RESULT* result = (CROSS_CHECK_RESULT*)Irp->AssociatedIrp.SystemBuffer;
	CROSS_CHECK_PROCESS_ENTRY* entries = (CROSS_CHECK_PROCESS_ENTRY*)((PUCHAR)result + sizeof(CROSS_CHECK_RESULT));
	RtlZeroMemory(result, requiredSize);

	/*
	 * Phase 1: Walk ActiveProcessLinks from the System process (PID 4).
	 * This is the linked list that DKOM attacks unlink processes from.
	 */
	ULONG linksCount = 0;
	{
		PEPROCESS systemProcess = NULL;
		status = PsLookupProcessByProcessId((HANDLE)4, &systemProcess);
		if (!NT_SUCCESS(status))
			return CompleteRequest(Irp, status, 0);

		PLIST_ENTRY listHead = (PLIST_ENTRY)((PUCHAR)systemProcess + g_EprocessOffsets.ActiveProcessLinksOffset);
		PLIST_ENTRY currentFlink = NULL;
		LIST_ENTRY currentEntry;

		/* Add System process itself first */
		{
			ULONG_PTR pid = 0;
			SafeReadPointer(systemProcess, g_EprocessOffsets.UniqueProcessIdOffset, &pid);
			entries[linksCount].ProcessId = (ULONG)pid;
			entries[linksCount].EprocessAddress = (unsigned long long)(ULONG_PTR)systemProcess;
			entries[linksCount].Sources = PROCESS_SOURCE_ACTIVE_LINKS;
			if (pPsGetProcessImageFileName) {
				PUCHAR name = pPsGetProcessImageFileName(systemProcess);
				if (name) {
					strncpy(entries[linksCount].ImageName, (const char*)name, 15);
					entries[linksCount].ImageName[15] = '\0';
				}
			}
			linksCount++;
		}

		/* Walk the linked list */
		if (SafeReadListEntry(listHead, &currentEntry)) {
			currentFlink = currentEntry.Flink;

			while (currentFlink != listHead && linksCount < MAX_CROSS_CHECK_PROCESSES) {
				PEPROCESS eprocess = (PEPROCESS)((PUCHAR)currentFlink - g_EprocessOffsets.ActiveProcessLinksOffset);
				ULONG_PTR pid = 0;

				if (!MmIsAddressValid(eprocess))
					break;

				SafeReadPointer(eprocess, g_EprocessOffsets.UniqueProcessIdOffset, &pid);

				entries[linksCount].ProcessId = (ULONG)pid;
				entries[linksCount].EprocessAddress = (unsigned long long)(ULONG_PTR)eprocess;
				entries[linksCount].Sources = PROCESS_SOURCE_ACTIVE_LINKS;

				if (pPsGetProcessImageFileName) {
					PUCHAR name = pPsGetProcessImageFileName(eprocess);
					if (name) {
						strncpy(entries[linksCount].ImageName, (const char*)name, 15);
						entries[linksCount].ImageName[15] = '\0';
					}
				}

				linksCount++;

				/* Walk to next entry */
				if (!SafeReadListEntry(currentFlink, &currentEntry))
					break;
				currentFlink = currentEntry.Flink;
			}
		}

		ObDereferenceObject(systemProcess);
	}

	result->ActiveLinksCount = linksCount;

	/*
	 * Phase 2: Brute-force PspCidTable via PsLookupProcessByProcessId.
	 * PIDs are multiples of 4 on Windows. Scan 0..65536.
	 */
	ULONG cidCount = 0;
	{
		ULONG pid;
		for (pid = 0; pid <= 65536; pid += 4) {
			PEPROCESS eprocess = NULL;
			status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &eprocess);
			if (!NT_SUCCESS(status))
				continue;

			/* Check if this PID is already in our list from Phase 1 */
			BOOLEAN found = FALSE;
			ULONG i;
			for (i = 0; i < linksCount; i++) {
				if (entries[i].ProcessId == pid) {
					entries[i].Sources |= PROCESS_SOURCE_CID_TABLE;
					found = TRUE;
					break;
				}
			}

			if (!found) {
				/* Process in CID table but NOT in ActiveProcessLinks = potentially DKOM'd */
				ULONG idx = linksCount + cidCount;
				if (idx < MAX_CROSS_CHECK_PROCESSES) {
					entries[idx].ProcessId = pid;
					entries[idx].EprocessAddress = (unsigned long long)(ULONG_PTR)eprocess;
					entries[idx].Sources = PROCESS_SOURCE_CID_TABLE;

					if (pPsGetProcessImageFileName) {
						PUCHAR name = pPsGetProcessImageFileName(eprocess);
						if (name) {
							strncpy(entries[idx].ImageName, (const char*)name, 15);
							entries[idx].ImageName[15] = '\0';
						}
					}

					cidCount++;
				}
			}

			ObDereferenceObject(eprocess);
		}
	}

	result->CidTableCount = cidCount;
	/* Count how many have CID_TABLE set from the merged entries */
	{
		ULONG totalCid = 0;
		ULONG i;
		for (i = 0; i < linksCount; i++) {
			if (entries[i].Sources & PROCESS_SOURCE_CID_TABLE)
				totalCid++;
		}
		result->CidTableCount = totalCid + cidCount;
	}

	result->TotalEntries = linksCount + cidCount;
	result->SuspiciousCount = cidCount; /* CID-only = unlinked from ActiveProcessLinks */

	return CompleteRequest(Irp, STATUS_SUCCESS,
		sizeof(CROSS_CHECK_RESULT) + sizeof(CROSS_CHECK_PROCESS_ENTRY) * result->TotalEntries);
}
