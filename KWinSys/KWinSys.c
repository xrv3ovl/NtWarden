#include "pch.h"
#include <wdm.h>
#include "Callbacks.h"
#include "KernelRuntime.h"
#include "KWinSysPublic.h"
#include "Modules.h"
#include "Ssdt.h"

#include "ProcessObjects.h"
#include "Gdt.h"
#include "Idt.h"
#include "IrpDispatch.h"
#include "ObjectProc.h"
#include "IoTimerEnum.h"
#include "Wfp.h"
#include "SecurityHandlers.h"
#include "Memory.h"

#include "KernelLog.h"

void WinSysUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS WinSysCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS WinSysDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING registryPath) {
	UNREFERENCED_PARAMETER(registryPath);
	PDEVICE_OBJECT devObj;
	UNICODE_STRING devName = RTL_CONSTANT_STRING(DEVICE_NAME);
	NTSTATUS status;

	status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &devObj);
	if (!NT_SUCCESS(status)) {
		KdPrint((DRIVER_PREFIX "Failed to create device object (0x%X)\n", status));
		return status;
	}

	{
		UNICODE_STRING symName = RTL_CONSTANT_STRING(L"\\??\\KWinSys");
		status = IoCreateSymbolicLink(&symName, &devName);
		if (!NT_SUCCESS(status)) {
			IoDeleteDevice(devObj);
			KdPrint((DRIVER_PREFIX "Failed to create symbolic link (0x%X)\n", status));
			return status;
		}
	}

	WinSysInitializeKernelLog();

	DriverObject->DriverUnload = WinSysUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverObject->MajorFunction[IRP_MJ_CLOSE] = WinSysCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = WinSysDeviceControl;

	status = WinSysInitializeRuntime();
	if (!NT_SUCCESS(status))
		KdPrint((DRIVER_PREFIX "Runtime initialization failed (0x%X)\n", status));
	else
		KdPrint((DRIVER_PREFIX "Runtime initialization succeeded\n"));

	return STATUS_SUCCESS;
}

void WinSysUnload(PDRIVER_OBJECT DriverObject) {
	UNICODE_STRING symName = RTL_CONSTANT_STRING(L"\\??\\KWinSys");

	WinSysShutdownKernelLog();
	IoDeleteSymbolicLink(&symName);
	IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS WinSysCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	return CompleteRequest(Irp, STATUS_SUCCESS, 0);
}

NTSTATUS WinSysDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	PIO_STACK_LOCATION stack;
	DWORD code;

	UNREFERENCED_PARAMETER(DeviceObject);
	stack = IoGetCurrentIrpStackLocation(Irp);
	code = stack->Parameters.DeviceIoControl.IoControlCode;

	switch (code) {
	case IOCTL_WINSYS_GET_VERSION:
		if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(USHORT))
			return CompleteRequest(Irp, STATUS_BUFFER_TOO_SMALL, 0);
		*(USHORT*)Irp->AssociatedIrp.SystemBuffer = KWINSYS_PROTOCOL_VERSION;
		return CompleteRequest(Irp, STATUS_SUCCESS, sizeof(USHORT));
	case IOCTL_WINSYS_LIST_CALLBACKS:
		return WinSysHandleListCallbacks(Irp, stack);
	case IOCTL_WINSYS_LIST_SSDT:
		return WinSysHandleListSsdt(Irp, stack);
	case IOCTL_WINSYS_CREATE_MODULE_SNAPSHOT:
		return WinSysHandleCreateModuleSnapshot(Irp, stack);
	case IOCTL_WINSYS_QUERY_MODULE_PAGE:
		return WinSysHandleQueryModulePage(Irp, stack);
	case IOCTL_WINSYS_RELEASE_MODULE_SNAPSHOT:
		return WinSysHandleReleaseModuleSnapshot(Irp, stack);
	case IOCTL_WINSYS_LIST_MODULES:
		return WinSysHandleListModules(Irp, stack);
	case IOCTL_WINSYS_ENUM_PROCESS_OBJECTS:
		return WinSysHandleEnumProcessObjects(Irp, stack);
	case IOCTL_WINSYS_SET_EPROCESS_OFFSETS:
		return WinSysHandleSetEprocessOffsets(Irp, stack);
	case IOCTL_WINSYS_CROSS_CHECK_PROCESSES:
		return WinSysHandleCrossCheckProcesses(Irp, stack);
	case IOCTL_WINSYS_QUERY_GDT:
		return WinSysHandleQueryGdt(Irp, stack);
	case IOCTL_WINSYS_QUERY_IDT:
		return WinSysHandleQueryIdt(Irp, stack);
case IOCTL_WINSYS_QUERY_IRP_DISPATCH:
		return WinSysHandleQueryIrpDispatch(Irp, stack);
	case IOCTL_WINSYS_QUERY_OBJECT_PROCS:
		return WinSysHandleQueryObjectProcs(Irp, stack);
	case IOCTL_WINSYS_ENUM_IO_TIMERS:
		return WinSysHandleEnumIoTimers(Irp, stack);
	case IOCTL_WINSYS_ENUM_WFP_FILTERS:
		return WinSysHandleEnumWfpFilters(Irp, stack);
	case IOCTL_WINSYS_ENUM_WFP_CALLOUTS:
		return WinSysHandleEnumWfpCallouts(Irp, stack);
	case IOCTL_WINSYS_QUERY_INSTRUMENTATION_CB:
		return WinSysHandleQueryInstrumentationCb(Irp, stack);
	case IOCTL_WINSYS_SNAPSHOT_CALLBACKS:
		return WinSysHandleSnapshotCallbacks(Irp, stack);
	case IOCTL_WINSYS_DIFF_CALLBACKS:
		return WinSysHandleDiffCallbacks(Irp, stack);
	case IOCTL_WINSYS_ENUM_APC:
		return WinSysHandleEnumApc(Irp, stack);
	case IOCTL_WINSYS_QUERY_DSE_STATUS:
		return WinSysHandleQueryDseStatus(Irp, stack);
	case IOCTL_WINSYS_QUERY_KERNEL_INTEGRITY:
		return WinSysHandleQueryKernelIntegrity(Irp, stack);
	case IOCTL_WINSYS_QUERY_PATCHGUARD_TIMERS:
		return WinSysHandleQueryPatchGuardTimers(Irp, stack);
	case IOCTL_WINSYS_MEMORY_READ:
		return WinSysHandleMemoryRead(Irp, stack);
	case IOCTL_WINSYS_MEMORY_WRITE:
		return WinSysHandleMemoryWrite(Irp, stack);
case IOCTL_WINSYS_QUERY_KERNEL_LOGS:
		return WinSysHandleQueryKernelLogs(Irp, stack);
	default:
		return CompleteRequest(Irp, STATUS_INVALID_DEVICE_REQUEST, 0);
	}
}


