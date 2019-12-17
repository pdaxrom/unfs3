#ifndef __NTFSEA__
#define __NTFSEA__

#include <winternl.h>
#include <ntstatus.h>
#include <tchar.h>

#define DLL_EXPORT __declspec(dllexport)

#define MAX_LIST_LEN 4096
#define MAX_EA_VALUE 256

#define MAX_GETEA (sizeof(FILE_GET_EA_INFORMATION) + MAX_EA_VALUE)
#define MAX_FULLEA (sizeof(FILE_FULL_EA_INFORMATION) + 2 * MAX_EA_VALUE)

typedef struct _FILE_GET_EA_INFORMATION
{
	ULONG NextEntryOffset;
	UCHAR EaNameLength;
	CHAR EaName[1];
} FILE_GET_EA_INFORMATION, *PFILE_GET_EA_INFORMATION;

struct Ea
{
	CHAR Name[MAX_EA_VALUE];
	ULONG32 ValueLength;
	CHAR Value[MAX_EA_VALUE];
};

struct EaList
{
	ULONG32 ListSize;
	struct Ea List[MAX_LIST_LEN];
};

DLL_EXPORT struct EaList* GetEaList(PWSTR FileName);
DLL_EXPORT struct Ea* GetEa(PWSTR FileName, PSTR EaName);
DLL_EXPORT LONG32 WriteEa(PWSTR FileName, PSTR EaName, PSTR EaValue, ULONG32 EaValueLength);

BOOL WSL_getMode(PWSTR FileName, mode_t *Mode);
BOOL WSL_setMode(PWSTR FileName, mode_t Mode);

#endif
