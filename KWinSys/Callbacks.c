#include "pch.h"
#include <aux_klib.h>
#include <string.h>
#include "Callbacks.h"

static BOOLEAN IsReadablePtr(PVOID address) {
	return address != NULL && MmIsAddressValid(address);
}

static BOOLEAN TryReadPointer64(ULONG64 address, PULONG64 value) {
	if (!value || !IsReadablePtr((PVOID)address))
		return FALSE;

	__try {
		*value = *(volatile ULONG64*)address;
		return TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}
}

static BOOLEAN TryReadUlong(ULONG64 address, PULONG value) {
	if (!value || !IsReadablePtr((PVOID)address))
		return FALSE;

	__try {
		*value = *(volatile ULONG*)address;
		return TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}
}

static BOOLEAN HasOutputCapacity(MODULE_INFO* current, MODULE_INFO* outStart, ULONG maxEntries) {
	if (!current || !outStart)
		return FALSE;
	return (ULONG)(current - outStart) < maxEntries;
}

static ULONG64 DecodeExFastRef(ULONG64 value) {
#ifdef _WIN64
	return value & ~0xFull;
#else
	return value & ~0x7ull;
#endif
}

static ULONG64 FindRipRelativeLeaTarget(ULONG64 functionAddr, ULONG scanLength, BOOLEAN allow4C2D, BOOLEAN allow480D, BOOLEAN allow4815) {
	ULONG64 instructionAddr;
	LONG offsetAddr = 0;

	if (functionAddr == 0)
		return 0;

	for (instructionAddr = functionAddr; instructionAddr < functionAddr + scanLength; instructionAddr++) {
		/*
		 * Common x64 forms seen for resolving the notify array:
		 *   4C 8D 2D xx xx xx xx   lea r13, [rip+disp32]
		 *   48 8D 0D xx xx xx xx   lea rcx, [rip+disp32]
		 *   48 8D 15 xx xx xx xx   lea rdx, [rip+disp32]
		 */
		if ((allow4C2D &&
			*(PUCHAR)instructionAddr == 0x4C &&
			*(PUCHAR)(instructionAddr + 1) == 0x8D &&
			*(PUCHAR)(instructionAddr + 2) == 0x2D) ||
			(allow480D &&
				*(PUCHAR)instructionAddr == 0x48 &&
				*(PUCHAR)(instructionAddr + 1) == 0x8D &&
				*(PUCHAR)(instructionAddr + 2) == 0x0D) ||
			(allow4815 &&
				*(PUCHAR)instructionAddr == 0x48 &&
				*(PUCHAR)(instructionAddr + 1) == 0x8D &&
				*(PUCHAR)(instructionAddr + 2) == 0x15)) {
			RtlCopyMemory(&offsetAddr, (PUCHAR)(instructionAddr + 3), 4);
			return instructionAddr + 7 + offsetAddr;
		}
	}

	return 0;
}

static ULONG64 FindPspCreateProcessNotifyRoutine() {
	UNICODE_STRING func;
	ULONG64 funcAddr;
	ULONG64 instructionAddr;
	LONG offsetAddr = 0;

	RtlInitUnicodeString(&func, L"PsSetCreateProcessNotifyRoutineEx");
	funcAddr = (ULONG64)MmGetSystemRoutineAddress(&func);
	if (funcAddr != 0) {
		for (instructionAddr = funcAddr; instructionAddr < funcAddr + 32; instructionAddr++) {
			if (*(PUCHAR)instructionAddr == 0xE8) {
				RtlCopyMemory(&offsetAddr, (PUCHAR)(instructionAddr + 1), 4);
				funcAddr = instructionAddr + offsetAddr + 5;
				break;
			}
		}

		{
			ULONG64 target = FindRipRelativeLeaTarget(funcAddr, 0x120, TRUE, FALSE, FALSE);
			if (target != 0)
				return target;
		}
	}

	RtlInitUnicodeString(&func, L"PsSetCreateProcessNotifyRoutine");
	funcAddr = (ULONG64)MmGetSystemRoutineAddress(&func);
	if (funcAddr == 0)
		return 0;

	for (instructionAddr = funcAddr; instructionAddr < funcAddr + 20; instructionAddr++) {
		if (*(PUCHAR)instructionAddr == 0xe8) {
			RtlCopyMemory(&offsetAddr, (PUCHAR)(instructionAddr + 1), 4);
			funcAddr = instructionAddr + offsetAddr + 5;
			break;
		}
	}

	return FindRipRelativeLeaTarget(funcAddr, 0xFF, TRUE, FALSE, FALSE);
}

static ULONG64 FindPsSetCreateThreadNotifyRoutine() {
	UNICODE_STRING func;
	ULONG64 funcAddr;
	ULONG64 instructionAddr;
	LONG offsetAddr = 0;

	RtlInitUnicodeString(&func, L"PsSetCreateThreadNotifyRoutine");
	funcAddr = (ULONG64)MmGetSystemRoutineAddress(&func);

	for (instructionAddr = funcAddr; instructionAddr < funcAddr + 20; instructionAddr++) {
		if (*(PUCHAR)instructionAddr == 0xe8) {
			RtlCopyMemory(&offsetAddr, (PUCHAR)(instructionAddr + 1), 4);
			funcAddr = funcAddr + (instructionAddr - funcAddr) + offsetAddr + 5;
			break;
		}
	}

	for (instructionAddr = funcAddr; instructionAddr < funcAddr + 0xff; instructionAddr++) {
		if (*(PUCHAR)instructionAddr == 0x48 &&
			*(PUCHAR)(instructionAddr + 1) == 0x8d &&
			*(PUCHAR)(instructionAddr + 2) == 0x0d) {
			RtlCopyMemory(&offsetAddr, (PUCHAR)(instructionAddr + 3), 4);
			return offsetAddr + 7 + instructionAddr;
		}
	}
	return 0;
}

static ULONG64 FindPsLoadImageNotifyRoutineArray() {
	UNICODE_STRING func;
	ULONG64 funcAddr;
	ULONG64 instructionAddr;
	LONG offsetAddr = 0;
	PKERNEL_LAYOUT layout = WinSysGetKernelLayout();

	RtlInitUnicodeString(&func, layout->SupportsImageNotifyEx ? L"PsSetLoadImageNotifyRoutineEx" : L"PsSetLoadImageNotifyRoutine");
	funcAddr = (ULONG64)MmGetSystemRoutineAddress(&func);
	if (funcAddr == 0 && layout->SupportsImageNotifyEx) {
		RtlInitUnicodeString(&func, L"PsSetLoadImageNotifyRoutine");
		funcAddr = (ULONG64)MmGetSystemRoutineAddress(&func);
	}
	if (funcAddr == 0)
		return 0;

	for (instructionAddr = funcAddr; instructionAddr < funcAddr + 0xff; instructionAddr++) {
		if (*(PUCHAR)instructionAddr == 0x48 &&
			*(PUCHAR)(instructionAddr + 1) == 0x8d &&
			*(PUCHAR)(instructionAddr + 2) == 0x0d) {
			RtlCopyMemory(&offsetAddr, (PUCHAR)(instructionAddr + 3), 4);
			return offsetAddr + 7 + instructionAddr;
		}
	}
	return 0;
}

static ULONG64 FindCmCallbackListHead() {
	UNICODE_STRING func;
	ULONG64 funcAddr;
	ULONG64 instructionAddr;
	LONG offsetAddr = 0;

	RtlInitUnicodeString(&func, L"CmUnRegisterCallback");
	funcAddr = (ULONG64)MmGetSystemRoutineAddress(&func);

	for (instructionAddr = funcAddr; instructionAddr < funcAddr + 0xff; instructionAddr++) {
		if (*(PUCHAR)instructionAddr == 0x48 &&
			*(PUCHAR)(instructionAddr + 1) == 0x8d &&
			*(PUCHAR)(instructionAddr + 2) == 0x0d) {
			memcpy(&offsetAddr, (PUCHAR)(instructionAddr + 3), 4);
			return offsetAddr + 7 + instructionAddr;
		}
	}
	return 0;
}

static NTSTATUS GetModuleNameFromCallbackAddr(ULONG64 moduleAddr, PCHAR moduleName) {
	NTSTATUS status;
	ULONG modulesSize = 0;
	PAUX_MODULE_EXTENDED_INFO modules;
	ULONG numberOfModules;

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

	RtlZeroMemory(modules, modulesSize);
	status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), modules);
	if (NT_SUCCESS(status)) {
		for (ULONG i = 0; i < numberOfModules; i++) {
			if (moduleAddr > (ULONG64)modules[i].BasicInfo.ImageBase &&
				moduleAddr < ((ULONG64)modules[i].BasicInfo.ImageBase + modules[i].ImageSize)) {
				strcpy_s(moduleName, 150, (CHAR*)modules[i].FullPathName);
				break;
			}
		}
	}

	ExFreePoolWithTag(modules, DRIVER_TAG);
	return status;
}

static NTSTATUS EnumObCallbacksTyped(PVOID* callbackListHead, MODULE_INFO** outInfo, int preType, int postType) {
	NTSTATUS status = STATUS_SUCCESS;
	PLIST_ENTRY entry;
	PKERNEL_LAYOUT layout = WinSysGetKernelLayout();
	MODULE_INFO* outStart = *outInfo;
	const ULONG maxEntries = 200;
	ULONG walked = 0;
	ULONG emitted = 0;
	ULONG skippedInvalidLink = 0;
	ULONG skippedPreRead = 0;
	ULONG skippedPreModule = 0;
	ULONG skippedPostRead = 0;
	ULONG skippedPostModule = 0;

	if (!callbackListHead || !IsReadablePtr(callbackListHead) || !IsReadablePtr(*callbackListHead))
		return STATUS_INVALID_ADDRESS;

	KdPrint((DRIVER_PREFIX
		"EnumObCallbacksTyped: head=%p first=%p ops=0x%lx obj=0x%lx pre=0x%lx post=0x%lx types=(%d,%d)\n",
		callbackListHead,
		callbackListHead ? *callbackListHead : NULL,
		layout->ObCallbackEntryOperationsOffset,
		layout->ObCallbackEntryObjectTypeOffset,
		layout->ObCallbackEntryPreOperationOffset,
		layout->ObCallbackEntryPostOperationOffset,
		preType,
		postType));

	__try {
		for (entry = (PLIST_ENTRY)*callbackListHead; entry != (PLIST_ENTRY)callbackListHead; entry = (PLIST_ENTRY)entry->Flink) {
			ULONG64 preOpCallback = 0;
			ULONG operations = 0;
			ULONG64 objectType = 0;

			walked++;

			if (!IsReadablePtr(entry) || !IsReadablePtr(entry->Flink)) {
				skippedInvalidLink++;
				if (walked <= 8) {
					KdPrint((DRIVER_PREFIX "EnumObCallbacksTyped: invalid link at entry[%lu]=%p flink=%p\n",
						walked - 1,
						entry,
						entry ? entry->Flink : NULL));
				}
				break;
			}

			TryReadPointer64((ULONG64)((ULONG_PTR)entry + layout->ObCallbackEntryObjectTypeOffset), &objectType);
			if (walked <= 8) {
				KdPrint((DRIVER_PREFIX "EnumObCallbacksTyped: entry[%lu]=%p objectType=0x%llx flink=%p blink=%p\n",
					walked - 1,
					entry,
					objectType,
					entry->Flink,
					entry->Blink));
			}

			if (TryReadPointer64((ULONG64)((ULONG_PTR)entry + layout->ObCallbackEntryPreOperationOffset), &preOpCallback) &&
				IsReadablePtr((PVOID)preOpCallback)) {
				CHAR name[150] = { 0 };
				status = GetModuleNameFromCallbackAddr(preOpCallback, name);
				if (!NT_SUCCESS(status)) {
					skippedPreModule++;
					if (walked <= 8) {
						KdPrint((DRIVER_PREFIX "EnumObCallbacksTyped: pre[%lu]=0x%llx module lookup failed 0x%X\n",
							walked - 1,
							preOpCallback,
							status));
					}
					continue;
				}
				if (!HasOutputCapacity(*outInfo, outStart, maxEntries))
					return STATUS_SUCCESS;
				(*outInfo)->addr = preOpCallback;
				strcpy_s((*outInfo)->name, 150, name);
				(*outInfo)->type = preType;
				if (TryReadUlong((ULONG64)((ULONG_PTR)entry + layout->ObCallbackEntryOperationsOffset), &operations))
					(*outInfo)->operations = operations;
				if (walked <= 8) {
					KdPrint((DRIVER_PREFIX "EnumObCallbacksTyped: pre[%lu]=0x%llx ops=0x%lx module=%s\n",
						walked - 1,
						preOpCallback,
						operations,
						name));
				}
				(*outInfo)++;
				emitted++;
			}
			else if (walked <= 8) {
				skippedPreRead++;
				KdPrint((DRIVER_PREFIX "EnumObCallbacksTyped: pre[%lu] unreadable or null\n", walked - 1));
			}

			preOpCallback = 0;
			operations = 0;
			if (TryReadPointer64((ULONG64)((ULONG_PTR)entry + layout->ObCallbackEntryPostOperationOffset), &preOpCallback) &&
				IsReadablePtr((PVOID)preOpCallback)) {
				CHAR name[150] = { 0 };
				status = GetModuleNameFromCallbackAddr(preOpCallback, name);
				if (!NT_SUCCESS(status)) {
					skippedPostModule++;
					if (walked <= 8) {
						KdPrint((DRIVER_PREFIX "EnumObCallbacksTyped: post[%lu]=0x%llx module lookup failed 0x%X\n",
							walked - 1,
							preOpCallback,
							status));
					}
					continue;
				}
				if (!HasOutputCapacity(*outInfo, outStart, maxEntries))
					return STATUS_SUCCESS;
				(*outInfo)->addr = preOpCallback;
				strcpy_s((*outInfo)->name, 150, name);
				(*outInfo)->type = postType;
				if (TryReadUlong((ULONG64)((ULONG_PTR)entry + layout->ObCallbackEntryOperationsOffset), &operations))
					(*outInfo)->operations = operations;
				if (walked <= 8) {
					KdPrint((DRIVER_PREFIX "EnumObCallbacksTyped: post[%lu]=0x%llx ops=0x%lx module=%s\n",
						walked - 1,
						preOpCallback,
						operations,
						name));
				}
				(*outInfo)++;
				emitted++;
			}
			else if (walked <= 8) {
				skippedPostRead++;
				KdPrint((DRIVER_PREFIX "EnumObCallbacksTyped: post[%lu] unreadable or null\n", walked - 1));
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		KdPrint((DRIVER_PREFIX "EnumObCallbacksTyped: exception while walking callback list\n"));
		return STATUS_SUCCESS;
	}

	KdPrint((DRIVER_PREFIX
		"EnumObCallbacksTyped: walked=%lu emitted=%lu invalidLink=%lu preRead=%lu preModule=%lu postRead=%lu postModule=%lu types=(%d,%d)\n",
		walked,
		emitted,
		skippedInvalidLink,
		skippedPreRead,
		skippedPreModule,
		skippedPostRead,
		skippedPostModule,
		preType,
		postType));
	return status;
}

static NTSTATUS EnumCallbackArray(ULONG64 callbackArrayAddr, MODULE_INFO** outInfo, int type) {
	NTSTATUS status = STATUS_SUCCESS;
	ULONG64 i;
	MODULE_INFO* outStart = *outInfo;
	const ULONG maxEntries = 200;

	if (!callbackArrayAddr || !IsReadablePtr((PVOID)callbackArrayAddr))
		return STATUS_SUCCESS;

	for (i = 0; i < 64; i++) {
		ULONG64 slotAddr = callbackArrayAddr + i * sizeof(ULONG64);
		ULONG64 fastRefValue = 0;
		ULONG64 callbackBlock = 0;
		ULONG64 callbackFuncAddr = 0;

		if (!TryReadPointer64(slotAddr, &fastRefValue) || fastRefValue == 0)
			continue;

		callbackBlock = DecodeExFastRef(fastRefValue);
		if (!IsReadablePtr((PVOID)callbackBlock))
			continue;

		/*
		 * PspCreateProcessNotifyRoutine / PspCreateThreadNotifyRoutine /
		 * PspLoadImageNotifyRoutine store EX_FAST_REF entries that point to an
		 * EX_CALLBACK_ROUTINE_BLOCK. The callback function is the second pointer
		 * in that block, after the rundown reference.
		 */
		if (!TryReadPointer64(callbackBlock + sizeof(ULONG_PTR), &callbackFuncAddr) ||
			!IsReadablePtr((PVOID)callbackFuncAddr))
			continue;

		{
			CHAR name[150] = { 0 };
			status = GetModuleNameFromCallbackAddr(callbackFuncAddr, name);
			if (!NT_SUCCESS(status))
				continue;
			if (!HasOutputCapacity(*outInfo, outStart, maxEntries))
				return STATUS_SUCCESS;
			(*outInfo)->addr = callbackFuncAddr;
			strcpy_s((*outInfo)->name, 150, name);
			(*outInfo)->type = type;
			(*outInfo)++;
		}
	}
	return status;
}

static NTSTATUS ReadCallbackList(PVOID* callbackListHead, MODULE_INFO** outInfo, int type) {
	NTSTATUS status = STATUS_SUCCESS;
	PLIST_ENTRY entry;
	MODULE_INFO* outStart = *outInfo;
	const ULONG maxEntries = 200;

	if (!callbackListHead || !IsReadablePtr(callbackListHead) || !IsReadablePtr(*callbackListHead))
		return STATUS_INVALID_ADDRESS;

	__try {
		for (entry = (PLIST_ENTRY)*callbackListHead; entry != (PLIST_ENTRY)callbackListHead; entry = (PLIST_ENTRY)entry->Flink) {
			CHAR name[150] = { 0 };
			ULONG64 callbackAddr = 0;

			if (!IsReadablePtr(entry) || !IsReadablePtr(entry->Flink))
				break;
			if (!TryReadPointer64((ULONG64)((ULONG_PTR)entry + 0x028), &callbackAddr) || !IsReadablePtr((PVOID)callbackAddr))
				continue;
			status = GetModuleNameFromCallbackAddr(callbackAddr, name);
			if (!NT_SUCCESS(status))
				continue;
			if (!HasOutputCapacity(*outInfo, outStart, maxEntries))
				return STATUS_SUCCESS;
			(*outInfo)->addr = callbackAddr;
			strcpy_s((*outInfo)->name, 150, name);
			(*outInfo)->type = type;
			(*outInfo)++;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return STATUS_SUCCESS;
	}
	return status;
}

NTSTATUS WinSysHandleListCallbacks(PIRP Irp, PIO_STACK_LOCATION stack) {
	MODULE_INFO* outBuffer;
	MODULE_INFO* outStart;
	PVOID* callbackListHead;
	PVOID* threadCallbackListHead;
	PVOID* regCallbackListHead;
	ULONG64 processCallbackArray;
	ULONG64 threadCallbackArray;
	ULONG64 imageCallbackArray;
	PKERNEL_LAYOUT layout;
	CALLBACK_QUERY* query;
	ULONG objectTypeCallbackListOffset;
	ULONG_PTR bytesWritten;

	if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(CALLBACK_QUERY))
		return CompleteRequest(Irp, STATUS_INVALID_BUFFER_SIZE, 0);
	if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(MODULE_INFO) * 200)
		return CompleteRequest(Irp, STATUS_BUFFER_TOO_SMALL, 0);

	query = (CALLBACK_QUERY*)Irp->AssociatedIrp.SystemBuffer;
	outBuffer = (MODULE_INFO*)Irp->AssociatedIrp.SystemBuffer;
	outStart = outBuffer;
	RtlZeroMemory(outBuffer, sizeof(MODULE_INFO) * 200);

	processCallbackArray = query->ProcessNotifyArray;
	threadCallbackArray = query->ThreadNotifyArray;
	imageCallbackArray = query->ImageNotifyArray;
	regCallbackListHead = (PVOID*)query->RegistryCallbackListHead;
	layout = WinSysGetKernelLayout();
	objectTypeCallbackListOffset = query->ObjectTypeCallbackListOffset;

	/* Fallback to pattern scanning when public PDB lacks private symbols */
	if (!processCallbackArray) {
		processCallbackArray = FindPspCreateProcessNotifyRoutine();
		if (processCallbackArray)
			KdPrint((DRIVER_PREFIX "Callbacks: PspCreateProcessNotifyRoutine resolved via pattern scan: 0x%llx\n", processCallbackArray));
	}
	if (!threadCallbackArray) {
		threadCallbackArray = FindPsSetCreateThreadNotifyRoutine();
		if (threadCallbackArray)
			KdPrint((DRIVER_PREFIX "Callbacks: PspCreateThreadNotifyRoutine resolved via pattern scan: 0x%llx\n", threadCallbackArray));
	}
	if (!imageCallbackArray) {
		imageCallbackArray = FindPsLoadImageNotifyRoutineArray();
		if (imageCallbackArray)
			KdPrint((DRIVER_PREFIX "Callbacks: PspLoadImageNotifyRoutine resolved via pattern scan: 0x%llx\n", imageCallbackArray));
	}
	if (!regCallbackListHead) {
		regCallbackListHead = (PVOID*)FindCmCallbackListHead();
		if (regCallbackListHead)
			KdPrint((DRIVER_PREFIX "Callbacks: CallbackListHead resolved via pattern scan: 0x%llx\n", (ULONG64)regCallbackListHead));
	}

	if ((objectTypeCallbackListOffset == 0 || objectTypeCallbackListOffset == (ULONG)-1) &&
		layout->ObjectTypeCallbackListOffset != 0) {
		objectTypeCallbackListOffset = layout->ObjectTypeCallbackListOffset;
		KdPrint((DRIVER_PREFIX "Callbacks: using runtime OBJECT_TYPE.CallbackList offset 0x%lx (query=0x%lx)\n",
			objectTypeCallbackListOffset,
			query->ObjectTypeCallbackListOffset));
	}
	else {
		KdPrint((DRIVER_PREFIX "Callbacks: query Proc=0x%llx Thread=0x%llx Image=0x%llx Reg=0x%llx ObjOff=0x%lx\n",
			processCallbackArray,
			threadCallbackArray,
			imageCallbackArray,
			query->RegistryCallbackListHead,
			query->ObjectTypeCallbackListOffset));
	}

	if (processCallbackArray)
		EnumCallbackArray(processCallbackArray, &outBuffer, 1);
	if (threadCallbackArray)
		EnumCallbackArray(threadCallbackArray, &outBuffer, 2);
	if (imageCallbackArray)
		EnumCallbackArray(imageCallbackArray, &outBuffer, 3);
	if (regCallbackListHead)
		ReadCallbackList(regCallbackListHead, &outBuffer, 4);

	if (objectTypeCallbackListOffset != 0 && objectTypeCallbackListOffset != (ULONG)-1) {
		callbackListHead = (PVOID*)((PUCHAR)*PsProcessType + objectTypeCallbackListOffset);
		if (callbackListHead)
			EnumObCallbacksTyped(callbackListHead, &outBuffer, 5, 6);

		threadCallbackListHead = (PVOID*)((PUCHAR)*PsThreadType + objectTypeCallbackListOffset);
		if (threadCallbackListHead)
			EnumObCallbacksTyped(threadCallbackListHead, &outBuffer, 7, 8);
	}
	else {
		KdPrint((DRIVER_PREFIX "Callbacks: OBJECT_TYPE.CallbackList offset unavailable; skipping OB callback enumeration\n"));
	}

	bytesWritten = (ULONG_PTR)((PUCHAR)outBuffer - (PUCHAR)outStart);
	if (bytesWritten == 0)
		bytesWritten = sizeof(MODULE_INFO);

	KdPrint((DRIVER_PREFIX "Callbacks: returning %llu bytes (%lu entries)\n",
		(unsigned long long)bytesWritten,
		(ULONG)(bytesWritten / sizeof(MODULE_INFO))));

	return CompleteRequest(Irp, STATUS_SUCCESS, bytesWritten);
}
