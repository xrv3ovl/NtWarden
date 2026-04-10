#include "pch.h"
#include <wdm.h>
#include <string.h>
#include "KernelRuntime.h"

ZWQUERYSYSTEMINFORMATION g_ZwQSI = 0;
static KERNEL_LAYOUT g_KernelLayout = { 0 };

static ULONG64 FindCallbackListOffsetForObjectType(POBJECT_TYPE objectType) {
	if (!objectType || !MmIsAddressValid((PVOID)objectType))
		return 0;

	__try {
		for (LONG offset = 0xF8; offset >= (LONG)sizeof(PVOID) * 2; offset -= (LONG)sizeof(PVOID)) {
			PLIST_ENTRY listHead = (PLIST_ENTRY)((PUCHAR)objectType + offset);
			if (!MmIsAddressValid((PVOID)listHead) || !MmIsAddressValid((PVOID)listHead->Flink) || !MmIsAddressValid((PVOID)listHead->Blink))
				continue;

			PUCHAR firstEntry = (PUCHAR)listHead->Flink;
			if (!MmIsAddressValid((PVOID)firstEntry))
				continue;

			PVOID entryObjectType = *(PVOID*)(firstEntry + g_KernelLayout.ObCallbackEntryObjectTypeOffset);
			if (entryObjectType != objectType)
				continue;

			PVOID preOperation = *(PVOID*)(firstEntry + g_KernelLayout.ObCallbackEntryPreOperationOffset);
			PVOID postOperation = *(PVOID*)(firstEntry + g_KernelLayout.ObCallbackEntryPostOperationOffset);
			if ((preOperation && MmIsAddressValid(preOperation)) || (postOperation && MmIsAddressValid(postOperation))) {
				DbgPrint(DRIVER_PREFIX
					"FindCallbackListOffsetForObjectType: objectType=%p offset=0x%lx firstEntry=%p pre=%p post=%p\n",
					objectType,
					offset,
					firstEntry,
					preOperation,
					postOperation);
				return (ULONG64)offset;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint(DRIVER_PREFIX "FindCallbackListOffsetForObjectType: exception while scanning objectType=%p\n", objectType);
		return 0;
	}

	DbgPrint(DRIVER_PREFIX "FindCallbackListOffsetForObjectType: no callback list found for objectType=%p\n", objectType);
	return 0;
}

NTSTATUS NTAPI LOLZwQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL) {
	return g_ZwQSI(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}

NTSTATUS WinSysInitializeRuntime() {
	UNICODE_STRING routineName;

	if (!g_ZwQSI) {
		RtlInitUnicodeString(&routineName, L"ZwQuerySystemInformation");
		g_ZwQSI = (ZWQUERYSYSTEMINFORMATION)MmGetSystemRoutineAddress(&routineName);
		if (!g_ZwQSI)
			return STATUS_PROCEDURE_NOT_FOUND;
	}

	RtlZeroMemory(&g_KernelLayout, sizeof(g_KernelLayout));
	PsGetVersion(&g_KernelLayout.MajorVersion, &g_KernelLayout.MinorVersion, &g_KernelLayout.BuildNumber, NULL);
	g_KernelLayout.ObCallbackEntryOperationsOffset = 0x10;
	g_KernelLayout.ObCallbackEntryObjectTypeOffset = 0x20;
	g_KernelLayout.ObCallbackEntryPreOperationOffset = 0x28;
	g_KernelLayout.ObCallbackEntryPostOperationOffset = 0x30;
	g_KernelLayout.SupportsImageNotifyEx = g_KernelLayout.BuildNumber >= 14393 ? TRUE : FALSE;
	g_KernelLayout.ObjectTypeCallbackListOffset = (ULONG)FindCallbackListOffsetForObjectType(*PsProcessType);

	DbgPrint(DRIVER_PREFIX "Kernel layout: %lu.%lu.%lu, CallbackList=0x%lx, ImageNotifyEx=%s\n",
		g_KernelLayout.MajorVersion,
		g_KernelLayout.MinorVersion,
		g_KernelLayout.BuildNumber,
		g_KernelLayout.ObjectTypeCallbackListOffset,
		g_KernelLayout.SupportsImageNotifyEx ? "yes" : "no");

	return STATUS_SUCCESS;
}

PKERNEL_LAYOUT WinSysGetKernelLayout() {
	return &g_KernelLayout;
}

PVOID* FindObRegisterCallbacksListHead(POBJECT_TYPE objectType) {
	if (g_KernelLayout.ObjectTypeCallbackListOffset == 0)
		return NULL;
	return (PVOID*)((PUCHAR)objectType + g_KernelLayout.ObjectTypeCallbackListOffset);
}

NTSTATUS CompleteRequest(PIRP Irp, NTSTATUS status, ULONG_PTR information) {
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = information;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

PVOID GetKernelBase(PULONG pImageSize) {
	typedef struct _SYSTEM_MODULE_ENTRY {
		HANDLE Section;
		PVOID MappedBase;
		PVOID ImageBase;
		ULONG ImageSize;
		ULONG Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT OffsetToFileName;
		UCHAR FullPathName[256];
	} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

#pragma warning(disable:4200)
	typedef struct _LOCAL_SYSTEM_MODULE_INFORMATION {
		ULONG Count;
		SYSTEM_MODULE_ENTRY Module[0];
	} LOCAL_SYSTEM_MODULE_INFORMATION, * PLOCAL_SYSTEM_MODULE_INFORMATION;

	PVOID moduleBase = NULL;
	PLOCAL_SYSTEM_MODULE_INFORMATION systemInfoBuffer = NULL;
	ULONG systemInfoBufferSize = 0;
	NTSTATUS status = LOLZwQuerySystemInformation(SystemModuleInformation, &systemInfoBufferSize, 0, &systemInfoBufferSize);

	if (!systemInfoBufferSize)
		return NULL;

	systemInfoBuffer = (PLOCAL_SYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, systemInfoBufferSize * 2, 'uwPw');
	if (!systemInfoBuffer)
		return NULL;

	memset(systemInfoBuffer, 0, systemInfoBufferSize * 2);
	status = LOLZwQuerySystemInformation(SystemModuleInformation, systemInfoBuffer, systemInfoBufferSize * 2, &systemInfoBufferSize);
	if (NT_SUCCESS(status)) {
		moduleBase = systemInfoBuffer->Module[0].ImageBase;
		if (pImageSize)
			*pImageSize = systemInfoBuffer->Module[0].ImageSize;
	}

	ExFreePool(systemInfoBuffer);
	return moduleBase;
}
