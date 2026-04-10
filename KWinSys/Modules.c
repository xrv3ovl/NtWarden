#include "pch.h"
#include <aux_klib.h>
#include "Modules.h"

static KERNEL_MODULE_ENTRY* g_ModuleSnapshot = NULL;
static ULONG g_ModuleSnapshotCount = 0;

static void ReleaseSnapshot() {
	if (g_ModuleSnapshot) {
		ExFreePoolWithTag(g_ModuleSnapshot, DRIVER_TAG);
		g_ModuleSnapshot = NULL;
		g_ModuleSnapshotCount = 0;
	}
}

static NTSTATUS BuildSnapshot() {
	NTSTATUS status;
	ULONG modulesSize = 0;
	PAUX_MODULE_EXTENDED_INFO modules;
	ULONG numberOfModules;

	ReleaseSnapshot();

	status = AuxKlibInitialize();
	if (!NT_SUCCESS(status))
		return status;

	status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), NULL);
	if (!NT_SUCCESS(status) || modulesSize == 0)
		return status;

	numberOfModules = modulesSize / sizeof(AUX_MODULE_EXTENDED_INFO);
	modules = (AUX_MODULE_EXTENDED_INFO*)ExAllocatePoolWithTag(PagedPool, modulesSize, DRIVER_TAG);
	if (!modules)
		return STATUS_INSUFFICIENT_RESOURCES;

	g_ModuleSnapshot = (KERNEL_MODULE_ENTRY*)ExAllocatePoolWithTag(PagedPool, sizeof(KERNEL_MODULE_ENTRY) * numberOfModules, DRIVER_TAG);
	if (!g_ModuleSnapshot) {
		ExFreePoolWithTag(modules, DRIVER_TAG);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(modules, modulesSize);
	RtlZeroMemory(g_ModuleSnapshot, sizeof(KERNEL_MODULE_ENTRY) * numberOfModules);

	status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), modules);
	if (NT_SUCCESS(status)) {
		for (ULONG i = 0; i < numberOfModules; i++) {
			g_ModuleSnapshot[i].ImageBase = (ULONG64)modules[i].BasicInfo.ImageBase;
			g_ModuleSnapshot[i].ImageSize = modules[i].ImageSize;
			g_ModuleSnapshot[i].LoadOrderIndex = 0;
			g_ModuleSnapshot[i].InitOrderIndex = 0;
			g_ModuleSnapshot[i].LoadCount = 0;
			g_ModuleSnapshot[i].Flags = 0;
			strcpy_s(g_ModuleSnapshot[i].FullPath, sizeof(g_ModuleSnapshot[i].FullPath), (CHAR*)modules[i].FullPathName);
			strcpy_s(g_ModuleSnapshot[i].Name, sizeof(g_ModuleSnapshot[i].Name),
				(CHAR*)modules[i].FullPathName + modules[i].FileNameOffset);
		}
		g_ModuleSnapshotCount = numberOfModules;
	}
	else {
		ReleaseSnapshot();
	}

	ExFreePoolWithTag(modules, DRIVER_TAG);
	return status;
}

NTSTATUS WinSysHandleCreateModuleSnapshot(PIRP Irp, PIO_STACK_LOCATION stack) {
	UNREFERENCED_PARAMETER(stack);

	MODULE_SNAPSHOT_INFO* info = (MODULE_SNAPSHOT_INFO*)Irp->AssociatedIrp.SystemBuffer;
	NTSTATUS status = BuildSnapshot();
	if (!NT_SUCCESS(status))
		return CompleteRequest(Irp, status, 0);

	info->Count = g_ModuleSnapshotCount;
	return CompleteRequest(Irp, STATUS_SUCCESS, sizeof(MODULE_SNAPSHOT_INFO));
}

NTSTATUS WinSysHandleQueryModulePage(PIRP Irp, PIO_STACK_LOCATION stack) {
	MODULE_PAGE_REQUEST* request = (MODULE_PAGE_REQUEST*)Irp->AssociatedIrp.SystemBuffer;
	KERNEL_MODULE_ENTRY* outBuffer = (KERNEL_MODULE_ENTRY*)Irp->AssociatedIrp.SystemBuffer;
	ULONG availableCount;
	ULONG copyCount;

	if (!g_ModuleSnapshot || g_ModuleSnapshotCount == 0)
		return CompleteRequest(Irp, STATUS_INVALID_DEVICE_STATE, 0);

	if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(MODULE_PAGE_REQUEST))
		return CompleteRequest(Irp, STATUS_BUFFER_TOO_SMALL, 0);

	if (request->StartIndex >= g_ModuleSnapshotCount)
		return CompleteRequest(Irp, STATUS_INVALID_PARAMETER, 0);

	availableCount = g_ModuleSnapshotCount - request->StartIndex;
	copyCount = request->Count < availableCount ? request->Count : availableCount;
	if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(KERNEL_MODULE_ENTRY) * copyCount)
		return CompleteRequest(Irp, STATUS_BUFFER_TOO_SMALL, 0);

	RtlMoveMemory(outBuffer, g_ModuleSnapshot + request->StartIndex, sizeof(KERNEL_MODULE_ENTRY) * copyCount);
	return CompleteRequest(Irp, STATUS_SUCCESS, sizeof(KERNEL_MODULE_ENTRY) * copyCount);
}

NTSTATUS WinSysHandleReleaseModuleSnapshot(PIRP Irp, PIO_STACK_LOCATION stack) {
	UNREFERENCED_PARAMETER(stack);
	ReleaseSnapshot();
	return CompleteRequest(Irp, STATUS_SUCCESS, 0);
}

NTSTATUS WinSysHandleListModules(PIRP Irp, PIO_STACK_LOCATION stack) {
	return WinSysHandleCreateModuleSnapshot(Irp, stack);
}
