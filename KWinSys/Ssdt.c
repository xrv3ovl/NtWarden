#include "pch.h"
#include <stdbool.h>
#include <ntimage.h>
#include "Ssdt.h"

static SSDTStruct* SSDTfind() {
	static SSDTStruct* SSDT = 0;
	if (!SSDT) {
		ULONG kernelSize;
		ULONG_PTR kernelBase = (ULONG_PTR)GetKernelBase(&kernelSize);
		if (kernelBase == 0 || kernelSize == 0)
			return NULL;

		PIMAGE_NT_HEADERS ntHeaders = RtlImageNtHeader((PVOID)kernelBase);
		PIMAGE_SECTION_HEADER textSection = NULL;
		PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
		for (ULONG i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
			char sectionName[IMAGE_SIZEOF_SHORT_NAME + 1];
			RtlCopyMemory(sectionName, section->Name, IMAGE_SIZEOF_SHORT_NAME);
			sectionName[IMAGE_SIZEOF_SHORT_NAME] = '\0';
			if (strncmp(sectionName, ".text", sizeof(".text") - sizeof(char)) == 0) {
				textSection = section;
				break;
			}
			section++;
		}
		if (textSection == NULL)
			return NULL;

		{
			const unsigned char pattern[] = { 0x8B, 0xF8, 0xC1, 0xEF, 0x07, 0x83, 0xE7, 0x20, 0x25, 0xFF, 0x0F, 0x00, 0x00 };
			const ULONG signatureSize = sizeof(pattern);
			BOOLEAN found = FALSE;
			ULONG offset;
			for (offset = 0; offset < textSection->Misc.VirtualSize - signatureSize; offset++) {
				if (RtlCompareMemory(((unsigned char*)kernelBase + textSection->VirtualAddress + offset), pattern, signatureSize) == signatureSize) {
					ULONG_PTR address;
					LONG relativeOffset = 0;
					found = TRUE;
					address = kernelBase + textSection->VirtualAddress + offset + signatureSize;
					if ((*(unsigned char*)address == 0x4c) &&
						(*(unsigned char*)(address + 1) == 0x8d) &&
						(*(unsigned char*)(address + 2) == 0x15)) {
						relativeOffset = *(LONG*)(address + 3);
					}
					if (relativeOffset != 0)
						SSDT = (SSDTStruct*)(address + relativeOffset + 7);
					break;
				}
			}
			if (!found)
				return NULL;
		}
	}
	return SSDT;
}

NTSTATUS WinSysHandleListSsdt(PIRP Irp, PIO_STACK_LOCATION stack) {
	ULONG_PTR* outBuffer;
	SSDTStruct* ssdt;
	int i;

	if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(ULONG_PTR) * 500)
		return CompleteRequest(Irp, STATUS_BUFFER_TOO_SMALL, 0);

	outBuffer = (ULONG_PTR*)Irp->AssociatedIrp.SystemBuffer;
	RtlZeroMemory(outBuffer, sizeof(ULONG_PTR) * 500);

	ssdt = SSDTfind();
	if (!ssdt)
		return CompleteRequest(Irp, STATUS_NOT_FOUND, 0);

	{
		ULONG_PTR ssdtBase = (ULONG_PTR)ssdt->pServiceTable;
		ULONG maxServices = (ULONG)ssdt->NumberOfServices;
		if (maxServices > 500)
			maxServices = 500;
		for (i = 0; i < (int)maxServices; i++)
			outBuffer[i] = (ULONG_PTR)((ssdt->pServiceTable[i] >> 4) + ssdtBase);
	}

	return CompleteRequest(Irp, STATUS_SUCCESS, sizeof(ULONG_PTR) * 500);
}
