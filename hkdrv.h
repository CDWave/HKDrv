#pragma once
#include <ntifs.h>
#include <intrin.h>

// Windows build 对应 offsets
#define Win10_1803 17134
#define Win10_1809 17763
#define Win10_1903 18362
#define Win10_1909 18363
#define Win10_2004 19041
#define Win10_20H2 19042
#define Win10_21H1 19043
#define Win10_21H2 19044
#define Win10_22H2 19045
#define Win11_21H2 22000
#define Win11_22H2 22621

static const UINT64 PageMask = (~0xfull << 8) & 0xfffffffffull;

//请求结构
typedef struct _READ_WRITE_REQUEST
{
    UINT32 ProcessId;
    UINT64 Address;
    UINT64 Buffer;
    UINT64 Size;
    BOOLEAN Write;
} ReadWriteRequest, * PReadWriteRequest;

typedef struct _PROCESS_REQUEST
{
    UINT32 ProcessId;
} ProcessRequest, * PProcessRequest;

typedef struct _ALLOC_FREE_MEMORY_REQUEST
{
	UINT32 ProcessId;
	SIZE_T Size;
	PVOID Buffer;
	BOOLEAN Free;
} AllocFreeMemoryRequest, * PAllocFreeMemoryRequest;

typedef struct _DELETE_FILE_REQUEST
{
	UNICODE_STRING FilePath;
} DeleteFileRequest, * PDeleteFileRequest;

//一些必要的结构
typedef union _PS_PROTECTION
{
	UCHAR Level;
	struct
	{
		int Type : 3;
		int Audit : 1;
		int Signer : 4;
	} Flags;
} PS_PROTECTION, * PPS_PROTECTION;

typedef enum _PS_PROTECTED_SIGNER
{
	PsProtectedSignerNone = 0,
	PsProtectedSignerAuthenticode,
	PsProtectedSignerCodeGen,
	PsProtectedSignerAntimalware,
	PsProtectedSignerLsa,
	PsProtectedSignerWindows,
	PsProtectedSignerWinTcb,
	PsProtectedSignerWinSystem,
	PsProtectedSignerApp,
	PsProtectedSignerMax
} PS_PROTECTED_SIGNER, * PPS_PROTECTED_SIGNER;

typedef enum _PS_PROTECTED_TYPE
{
	PsProtectedTypeNone = 0,
	PsProtectedTypeProtectedLight = 1,
	PsProtectedTypeProtected = 2
} PS_PROTECTED_TYPE, * PPS_PROTECTED_TYPE;

typedef struct _LDR_DATA_TABLE_ENTRY64
{
	LIST_ENTRY64 InLoadOrderLinks;
	LIST_ENTRY64 InMemoryOrderLinks;
	LIST_ENTRY64 InInitializationOrderLinks;
	ULONG64 DllBase;
	ULONG64 EntryPoint;
	ULONG64 SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY64 HashLinks;
	ULONG64 SectionPointer;
	ULONG64 CheckSum;
	ULONG64 TimeDateStamp;
	ULONG64 LoadedImports;
	ULONG64 EntryPointActivationContext;
	ULONG64 PatchInformation;
	LIST_ENTRY64 ForwarderLinks;
	LIST_ENTRY64 ServiceTagLinks;
	LIST_ENTRY64 StaticLinks;
	ULONG64 ContextInformation;
	ULONG64 OriginalBase;
	LARGE_INTEGER LoadTime;
} LDR_DATA_TABLE_ENTRY64, * PLDR_DATA_TABLE_ENTRY64;

//自定义的IO控制码。自己定义时取0x800到0xFFF，因为0x0到0x7FF是微软保留的。
#define IOCTL_READ_WRITE	                CTL_CODE(FILE_DEVICE_UNKNOWN, 0x999, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_PROTECT_PROCESS	            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x998, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_DELETE_FILE					CTL_CODE(FILE_DEVICE_UNKNOWN, 0x997, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_KILL_PROCESS					CTL_CODE(FILE_DEVICE_UNKNOWN, 0x996, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_ALLOC_FREE_MEMORY				CTL_CODE(FILE_DEVICE_UNKNOWN, 0x995, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
