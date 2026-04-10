#pragma once

#include "KWinSys.h"

typedef NTSTATUS(NTAPI* ZWQUERYSYSTEMINFORMATION)(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	);

typedef struct _KERNEL_LAYOUT {
	ULONG MajorVersion;
	ULONG MinorVersion;
	ULONG BuildNumber;
	BOOLEAN SupportsImageNotifyEx;
	ULONG ObjectTypeCallbackListOffset;
	ULONG ObCallbackEntryOperationsOffset;
	ULONG ObCallbackEntryObjectTypeOffset;
	ULONG ObCallbackEntryPreOperationOffset;
	ULONG ObCallbackEntryPostOperationOffset;
} KERNEL_LAYOUT, * PKERNEL_LAYOUT;

extern ZWQUERYSYSTEMINFORMATION g_ZwQSI;

NTSTATUS NTAPI LOLZwQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

NTSTATUS WinSysInitializeRuntime();
PKERNEL_LAYOUT WinSysGetKernelLayout();
PVOID* FindObRegisterCallbacksListHead(POBJECT_TYPE objectType);
PVOID GetKernelBase(PULONG imageSize);
NTSTATUS CompleteRequest(PIRP Irp, NTSTATUS status, ULONG_PTR information);
