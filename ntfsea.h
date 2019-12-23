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

typedef struct _FILE_GET_EA_INFORMATION {
    ULONG NextEntryOffset;
    UCHAR EaNameLength;
    CHAR EaName[1];
} FILE_GET_EA_INFORMATION, *PFILE_GET_EA_INFORMATION;

struct Ea {
    CHAR Name[MAX_EA_VALUE];
    ULONG32 ValueLength;
    CHAR Value[MAX_EA_VALUE];
};

struct EaList {
    ULONG32 ListSize;
    struct Ea List[MAX_LIST_LEN];
};

typedef struct _LXSS_FILE_EXTENDED_ATTRIBUTES_V1
{
    USHORT Flags;
    USHORT Version;

    ULONG st_mode;       // Mode bit mask constants: https://msdn.microsoft.com/en-us/library/3kyc8381.aspx
    ULONG st_uid;        // Numeric identifier of user who owns file (Linux-specific).
    ULONG st_gid;        // Numeric identifier of group that owns the file (Linux-specific)
    ULONG st_rdev;       // Drive number of the disk containing the file.
    ULONG st_atime_nsec; // Time of last access of file (nano-seconds).
    ULONG st_mtime_nsec; // Time of last modification of file (nano-seconds).
    ULONG st_ctime_nsec; // Time of creation of file (nano-seconds).
    ULONG64 st_atime;    // Time of last access of file.
    ULONG64 st_mtime;    // Time of last modification of file.
    ULONG64 st_ctime;    // Time of creation of file.
} LXSS_FILE_EXTENDED_ATTRIBUTES_V1, *PLXSS_FILE_EXTENDED_ATTRIBUTES_V1;

DLL_EXPORT struct EaList *GetEaList(PWSTR FileName);
DLL_EXPORT struct Ea *GetEa(PWSTR FileName, PSTR EaName);
DLL_EXPORT LONG32 WriteEa(PWSTR FileName, PSTR EaName, PSTR EaValue, ULONG32 EaValueLength);

BOOL WSL_GetMode(PWSTR FileName, mode_t * Mode);
BOOL WSL_SetMode(PWSTR FileName, mode_t Mode);
BOOL WSL_Chown(PWSTR FileName, uid_t owner, uid_t group);
BOOL WSL_GetParameters(PWSTR FileName, mode_t *mode, uid_t *owner, uid_t *group, PLXSS_FILE_EXTENDED_ATTRIBUTES_V1 lxattrb, BOOL *uselxattrb);

#endif
