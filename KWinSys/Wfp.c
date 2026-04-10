#include "pch.h"
#include "KWinSysPublic.h"
#include "KernelRuntime.h"

/* NDIS must be included before WFP headers for NET_BUFFER_LIST etc. */
#pragma warning(push)
#pragma warning(disable: 4201) /* nameless struct/union */
#include <ndis.h>
#include <fwpmk.h>
#pragma warning(pop)

#pragma comment(lib, "fwpkclnt.lib")

static void GuidToStringA(const GUID* guid, char* buf, ULONG bufSize) {
	RtlStringCbPrintfA(buf, bufSize, "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		guid->Data1, guid->Data2, guid->Data3,
		guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3],
		guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7]);
}

NTSTATUS WinSysHandleEnumWfpFilters(PIRP Irp, PIO_STACK_LOCATION stack) {
	WFP_FILTER_RESULT* resultHeader;
	WFP_FILTER_ENTRY* entries;
	ULONG outputSize, maxEntries, entryCount = 0;
	HANDLE engineHandle = NULL;
	HANDLE enumHandle = NULL;
	NTSTATUS status;
	FWPM_FILTER0** filterArray = NULL;
	UINT32 numReturned;

	outputSize = stack->Parameters.DeviceIoControl.OutputBufferLength;
	if (outputSize < sizeof(WFP_FILTER_RESULT) + sizeof(WFP_FILTER_ENTRY))
		return CompleteRequest(Irp, STATUS_BUFFER_TOO_SMALL, 0);

	maxEntries = (outputSize - sizeof(WFP_FILTER_RESULT)) / sizeof(WFP_FILTER_ENTRY);
	if (maxEntries > MAX_WFP_FILTERS) maxEntries = MAX_WFP_FILTERS;

	resultHeader = (WFP_FILTER_RESULT*)Irp->AssociatedIrp.SystemBuffer;
	entries = (WFP_FILTER_ENTRY*)((PUCHAR)resultHeader + sizeof(WFP_FILTER_RESULT));
	RtlZeroMemory(resultHeader, sizeof(WFP_FILTER_RESULT));

	status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &engineHandle);
	if (!NT_SUCCESS(status))
		return CompleteRequest(Irp, status, 0);

	status = FwpmFilterCreateEnumHandle0(engineHandle, NULL, &enumHandle);
	if (!NT_SUCCESS(status)) {
		FwpmEngineClose0(engineHandle);
		return CompleteRequest(Irp, status, 0);
	}

	while (entryCount < maxEntries) {
		UINT32 i;
		numReturned = 0;
		status = FwpmFilterEnum0(engineHandle, enumHandle, 64, &filterArray, &numReturned);
		if (!NT_SUCCESS(status) || numReturned == 0)
			break;

		for (i = 0; i < numReturned && entryCount < maxEntries; i++) {
			FWPM_FILTER0* f = filterArray[i];
			WFP_FILTER_ENTRY* entry = &entries[entryCount];

			entry->FilterId = f->filterId;
			entry->ActionType = f->action.type;
			entry->Flags = f->flags;

			if (f->displayData.name) {
				wcsncpy_s(entry->DisplayName, sizeof(entry->DisplayName) / sizeof(entry->DisplayName[0]),
					f->displayData.name, _TRUNCATE);
			}

			GuidToStringA(&f->layerKey, entry->LayerName, sizeof(entry->LayerName));

			if (f->providerKey) {
				GuidToStringA(f->providerKey, entry->ProviderName, sizeof(entry->ProviderName));
			}

			entryCount++;
		}

		FwpmFreeMemory0((void**)&filterArray);
	}

	FwpmFilterDestroyEnumHandle0(engineHandle, enumHandle);
	FwpmEngineClose0(engineHandle);

	resultHeader->Count = entryCount;
	return CompleteRequest(Irp, STATUS_SUCCESS,
		sizeof(WFP_FILTER_RESULT) + entryCount * sizeof(WFP_FILTER_ENTRY));
}

NTSTATUS WinSysHandleEnumWfpCallouts(PIRP Irp, PIO_STACK_LOCATION stack) {
	WFP_CALLOUT_RESULT* resultHeader;
	WFP_CALLOUT_ENTRY* entries;
	ULONG outputSize, maxEntries, entryCount = 0;
	HANDLE engineHandle = NULL;
	HANDLE enumHandle = NULL;
	NTSTATUS status;
	FWPM_CALLOUT0** calloutArray = NULL;
	UINT32 numReturned;

	outputSize = stack->Parameters.DeviceIoControl.OutputBufferLength;
	if (outputSize < sizeof(WFP_CALLOUT_RESULT) + sizeof(WFP_CALLOUT_ENTRY))
		return CompleteRequest(Irp, STATUS_BUFFER_TOO_SMALL, 0);

	maxEntries = (outputSize - sizeof(WFP_CALLOUT_RESULT)) / sizeof(WFP_CALLOUT_ENTRY);
	if (maxEntries > MAX_WFP_CALLOUTS) maxEntries = MAX_WFP_CALLOUTS;

	resultHeader = (WFP_CALLOUT_RESULT*)Irp->AssociatedIrp.SystemBuffer;
	entries = (WFP_CALLOUT_ENTRY*)((PUCHAR)resultHeader + sizeof(WFP_CALLOUT_RESULT));
	RtlZeroMemory(resultHeader, sizeof(WFP_CALLOUT_RESULT));

	status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &engineHandle);
	if (!NT_SUCCESS(status))
		return CompleteRequest(Irp, status, 0);

	status = FwpmCalloutCreateEnumHandle0(engineHandle, NULL, &enumHandle);
	if (!NT_SUCCESS(status)) {
		FwpmEngineClose0(engineHandle);
		return CompleteRequest(Irp, status, 0);
	}

	while (entryCount < maxEntries) {
		UINT32 i;
		numReturned = 0;
		status = FwpmCalloutEnum0(engineHandle, enumHandle, 64, &calloutArray, &numReturned);
		if (!NT_SUCCESS(status) || numReturned == 0)
			break;

		for (i = 0; i < numReturned && entryCount < maxEntries; i++) {
			FWPM_CALLOUT0* c = calloutArray[i];
			WFP_CALLOUT_ENTRY* entry = &entries[entryCount];

			entry->CalloutId = c->calloutId;
			entry->Flags = c->flags;
			entry->ClassifyFunction = 0;
			entry->NotifyFunction = 0;
			entry->FlowDeleteFunction = 0;

			if (c->displayData.name) {
				wcsncpy_s(entry->DisplayName, sizeof(entry->DisplayName) / sizeof(entry->DisplayName[0]),
					c->displayData.name, _TRUNCATE);
			}

			GuidToStringA(&c->applicableLayer, entry->LayerName, sizeof(entry->LayerName));

			if (c->providerKey) {
				GuidToStringA(c->providerKey, entry->ProviderName, sizeof(entry->ProviderName));
			}

			entryCount++;
		}

		FwpmFreeMemory0((void**)&calloutArray);
	}

	FwpmCalloutDestroyEnumHandle0(engineHandle, enumHandle);
	FwpmEngineClose0(engineHandle);

	resultHeader->Count = entryCount;
	return CompleteRequest(Irp, STATUS_SUCCESS,
		sizeof(WFP_CALLOUT_RESULT) + entryCount * sizeof(WFP_CALLOUT_ENTRY));
}
