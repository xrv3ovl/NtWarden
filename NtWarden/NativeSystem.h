#pragma once

#include <Windows.h>
#include <winternl.h>

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#endif

constexpr SYSTEM_INFORMATION_CLASS SystemObjectInformationClass =
	static_cast<SYSTEM_INFORMATION_CLASS>(17);
constexpr SYSTEM_INFORMATION_CLASS SystemPoolTagInformationClass =
	static_cast<SYSTEM_INFORMATION_CLASS>(22);
constexpr SYSTEM_INFORMATION_CLASS SystemInterruptInformationClass =
	static_cast<SYSTEM_INFORMATION_CLASS>(23);
constexpr SYSTEM_INFORMATION_CLASS SystemExtendedHandleInformationClass =
	static_cast<SYSTEM_INFORMATION_CLASS>(64);
constexpr SYSTEM_INFORMATION_CLASS SystemBigPoolInformationClass =
	static_cast<SYSTEM_INFORMATION_CLASS>(66);

typedef struct _SYSTEM_POOLTAG {
	union {
		UCHAR Tag[4];
		ULONG TagUlong;
	};
	ULONG PagedAllocs;
	ULONG PagedFrees;
	SIZE_T PagedUsed;
	ULONG NonPagedAllocs;
	ULONG NonPagedFrees;
	SIZE_T NonPagedUsed;
} SYSTEM_POOLTAG, *PSYSTEM_POOLTAG;

typedef struct _SYSTEM_POOLTAG_INFORMATION {
	ULONG Count;
	SYSTEM_POOLTAG TagInfo[1];
} SYSTEM_POOLTAG_INFORMATION, *PSYSTEM_POOLTAG_INFORMATION;

typedef struct _SYSTEM_BIGPOOL_ENTRY {
	union {
		PVOID VirtualAddress;
		ULONG_PTR VirtualAddressAndFlags;
		ULONG_PTR NonPaged : 1;
	};
	SIZE_T SizeInBytes;
	union {
		UCHAR Tag[4];
		ULONG TagUlong;
	};
} SYSTEM_BIGPOOL_ENTRY, *PSYSTEM_BIGPOOL_ENTRY;

typedef struct _SYSTEM_BIGPOOL_INFORMATION {
	ULONG_PTR Count;
	SYSTEM_BIGPOOL_ENTRY AllocatedInfo[1];
} SYSTEM_BIGPOOL_INFORMATION, *PSYSTEM_BIGPOOL_INFORMATION;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
	PVOID Object;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR HandleValue;
	ULONG GrantedAccess;
	USHORT CreatorBackTraceIndex;
	USHORT ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
	ULONG_PTR NumberOfHandles;
	ULONG_PTR Reserved;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

typedef struct _SYSTEM_OBJECTTYPE_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfObjects;
	ULONG NumberOfHandles;
	ULONG TypeIndex;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	ULONG PoolType;
	BOOLEAN SecurityRequired;
	BOOLEAN WaitableObject;
	UNICODE_STRING TypeName;
} SYSTEM_OBJECTTYPE_INFORMATION, *PSYSTEM_OBJECTTYPE_INFORMATION;

typedef struct _SYSTEM_INTERRUPT_INFORMATION_PRIVATE {
	ULONG ContextSwitches;
	ULONG DpcCount;
	ULONG DpcRate;
	ULONG TimeIncrement;
	ULONG DpcBypassCount;
	ULONG ApcBypassCount;
} SYSTEM_INTERRUPT_INFORMATION_PRIVATE, *PSYSTEM_INTERRUPT_INFORMATION_PRIVATE;
