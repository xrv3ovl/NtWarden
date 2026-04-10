#include "pch.h"
#include "KWinSysPublic.h"
#include "KernelRuntime.h"

/* Undocumented ntoskrnl export */
NTSYSAPI NTSTATUS NTAPI ObReferenceObjectByName(
	PUNICODE_STRING ObjectName,
	ULONG Attributes,
	PACCESS_STATE AccessState,
	ACCESS_MASK DesiredAccess,
	POBJECT_TYPE ObjectType,
	KPROCESSOR_MODE AccessMode,
	PVOID ParseContext,
	PVOID* Object);

extern POBJECT_TYPE* IoDriverObjectType;

NTSTATUS WinSysHandleQueryIrpDispatch(PIRP Irp, PIO_STACK_LOCATION stack) {
	IRP_DISPATCH_REQUEST* request;
	IRP_DISPATCH_RESULT* result;
	UNICODE_STRING driverName;
	PDRIVER_OBJECT driverObj = NULL;
	NTSTATUS status;
	int i;

	if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(IRP_DISPATCH_REQUEST) ||
		stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(IRP_DISPATCH_RESULT))
		return CompleteRequest(Irp, STATUS_BUFFER_TOO_SMALL, 0);

	request = (IRP_DISPATCH_REQUEST*)Irp->AssociatedIrp.SystemBuffer;
	result = (IRP_DISPATCH_RESULT*)Irp->AssociatedIrp.SystemBuffer;

	/* Ensure null termination */
	request->DriverName[255] = L'\0';
	RtlInitUnicodeString(&driverName, request->DriverName);

	status = ObReferenceObjectByName(
		&driverName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		0,
		*IoDriverObjectType,
		KernelMode,
		NULL,
		(PVOID*)&driverObj);

	if (!NT_SUCCESS(status))
		return CompleteRequest(Irp, status, 0);

	RtlZeroMemory(result, sizeof(IRP_DISPATCH_RESULT));
	result->DriverObjectAddress = (ULONG_PTR)driverObj;
	result->Count = IRP_MJ_MAXIMUM_FUNCTION_COUNT;

	__try {
		for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION_COUNT; i++) {
			result->Entries[i].HandlerAddress = (ULONG_PTR)driverObj->MajorFunction[i];
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		ObDereferenceObject(driverObj);
		return CompleteRequest(Irp, GetExceptionCode(), 0);
	}

	ObDereferenceObject(driverObj);
	return CompleteRequest(Irp, STATUS_SUCCESS, sizeof(IRP_DISPATCH_RESULT));
}
