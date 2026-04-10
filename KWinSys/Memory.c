#include "pch.h"
#include "Memory.h"

static BOOLEAN WinSysIsAddressRangeValid(PVOID address, SIZE_T size) {
	PUCHAR page;
	PUCHAR end;

	if (size == 0)
		return TRUE;
	if (address == NULL)
		return FALSE;
	if ((ULONG_PTR)address + size < (ULONG_PTR)address)
		return FALSE;

	page = (PUCHAR)((ULONG_PTR)address & ~(PAGE_SIZE - 1));
	end = (PUCHAR)address + size - 1;
	while (page <= end) {
		if (!MmIsAddressValid(page))
			return FALSE;
		if ((ULONG_PTR)page + PAGE_SIZE < (ULONG_PTR)page)
			break;
		page += PAGE_SIZE;
	}

	return MmIsAddressValid(end);
}

static NTSTATUS WinSysReadProcessMemory(ULONG pid, PVOID address, PVOID buffer, SIZE_T size) {
	PEPROCESS process;
	KAPC_STATE apcState;
	NTSTATUS status;

	status = PsLookupProcessByProcessId(ULongToHandle(pid), &process);
	if (!NT_SUCCESS(status))
		return status;

	KeStackAttachProcess(process, &apcState);
	status = STATUS_SUCCESS;
	__try {
		RtlCopyMemory(buffer, address, size);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		status = GetExceptionCode();
	}
	KeUnstackDetachProcess(&apcState);
	ObDereferenceObject(process);
	return status;
}

static NTSTATUS WinSysWriteProcessMemory(ULONG pid, PVOID address, PVOID buffer, SIZE_T size) {
	PEPROCESS process;
	KAPC_STATE apcState;
	NTSTATUS status;

	status = PsLookupProcessByProcessId(ULongToHandle(pid), &process);
	if (!NT_SUCCESS(status))
		return status;

	KeStackAttachProcess(process, &apcState);
	status = STATUS_SUCCESS;
	__try {
		RtlCopyMemory(address, buffer, size);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		status = GetExceptionCode();
	}
	KeUnstackDetachProcess(&apcState);
	ObDereferenceObject(process);
	return status;
}

NTSTATUS WinSysHandleMemoryRead(PIRP Irp, PIO_STACK_LOCATION stack) {
	MEMORY_READ_REQUEST request;
	MEMORY_READ_RESULT* result;
	NTSTATUS status;

	if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(MEMORY_READ_REQUEST) ||
		stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(MEMORY_READ_RESULT))
		return CompleteRequest(Irp, STATUS_BUFFER_TOO_SMALL, 0);

	RtlCopyMemory(&request, Irp->AssociatedIrp.SystemBuffer, sizeof(request));
	KdPrint((DRIVER_PREFIX "MemoryRead: request pid=%lu address=0x%llX size=%lu\n",
		request.Pid, request.Address, request.Size));
	if (request.Size > sizeof(result->Data)) {
		KdPrint((DRIVER_PREFIX "MemoryRead: invalid size %lu\n", request.Size));
		return CompleteRequest(Irp, STATUS_INVALID_PARAMETER, 0);
	}

	result = (MEMORY_READ_RESULT*)Irp->AssociatedIrp.SystemBuffer;
	RtlZeroMemory(result, sizeof(MEMORY_READ_RESULT));
	if (request.Size == 0)
		return CompleteRequest(Irp, STATUS_SUCCESS, sizeof(MEMORY_READ_RESULT));

	if (request.Pid == 0) {
		if (!WinSysIsAddressRangeValid((PVOID)(ULONG_PTR)request.Address, request.Size)) {
			KdPrint((DRIVER_PREFIX "MemoryRead: invalid kernel address 0x%llX\n", request.Address));
			return CompleteRequest(Irp, STATUS_ACCESS_VIOLATION, 0);
		}

		status = STATUS_SUCCESS;
		__try {
			RtlCopyMemory(result->Data, (PVOID)(ULONG_PTR)request.Address, request.Size);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			status = GetExceptionCode();
		}
	}
	else {
		status = WinSysReadProcessMemory(request.Pid, (PVOID)(ULONG_PTR)request.Address, result->Data, request.Size);
	}

	if (!NT_SUCCESS(status)) {
		KdPrint((DRIVER_PREFIX "MemoryRead failed for pid=%lu address=0x%llX status=0x%X\n",
			request.Pid, request.Address, status));
		return CompleteRequest(Irp, status, 0);
	}

	result->BytesRead = request.Size;
	KdPrint((DRIVER_PREFIX "MemoryRead: completed pid=%lu address=0x%llX bytes=%lu\n",
		request.Pid, request.Address, result->BytesRead));
	return CompleteRequest(Irp, STATUS_SUCCESS, sizeof(MEMORY_READ_RESULT));
}

NTSTATUS WinSysHandleMemoryWrite(PIRP Irp, PIO_STACK_LOCATION stack) {
	MEMORY_WRITE_REQUEST request;
	MEMORY_WRITE_RESULT* result;
	NTSTATUS status;

	if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(MEMORY_WRITE_REQUEST) ||
		stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(MEMORY_WRITE_RESULT))
		return CompleteRequest(Irp, STATUS_BUFFER_TOO_SMALL, 0);

	RtlCopyMemory(&request, Irp->AssociatedIrp.SystemBuffer, sizeof(request));
	KdPrint((DRIVER_PREFIX "MemoryWrite: request pid=%lu address=0x%llX size=%lu\n",
		request.Pid, request.Address, request.Size));
	if (request.Size > sizeof(request.Data)) {
		KdPrint((DRIVER_PREFIX "MemoryWrite: invalid size %lu\n", request.Size));
		return CompleteRequest(Irp, STATUS_INVALID_PARAMETER, 0);
	}

	result = (MEMORY_WRITE_RESULT*)Irp->AssociatedIrp.SystemBuffer;
	RtlZeroMemory(result, sizeof(MEMORY_WRITE_RESULT));
	if (request.Size == 0)
		return CompleteRequest(Irp, STATUS_SUCCESS, sizeof(MEMORY_WRITE_RESULT));

	if (request.Pid == 0) {
		if (!WinSysIsAddressRangeValid((PVOID)(ULONG_PTR)request.Address, request.Size)) {
			KdPrint((DRIVER_PREFIX "MemoryWrite: invalid kernel address 0x%llX\n", request.Address));
			return CompleteRequest(Irp, STATUS_ACCESS_VIOLATION, 0);
		}

		status = STATUS_SUCCESS;
		__try {
			RtlCopyMemory((PVOID)(ULONG_PTR)request.Address, request.Data, request.Size);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			status = GetExceptionCode();
		}
	}
	else {
		status = WinSysWriteProcessMemory(request.Pid, (PVOID)(ULONG_PTR)request.Address, request.Data, request.Size);
	}

	if (!NT_SUCCESS(status)) {
		KdPrint((DRIVER_PREFIX "MemoryWrite failed for pid=%lu address=0x%llX status=0x%X\n",
			request.Pid, request.Address, status));
		return CompleteRequest(Irp, status, 0);
	}

	result->BytesWritten = request.Size;
	KdPrint((DRIVER_PREFIX "MemoryWrite: completed pid=%lu address=0x%llX bytes=%lu\n",
		request.Pid, request.Address, result->BytesWritten));
	return CompleteRequest(Irp, STATUS_SUCCESS, sizeof(MEMORY_WRITE_RESULT));
}
