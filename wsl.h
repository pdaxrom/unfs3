#ifndef __WSL_H__
#define __WSL_H__

#define SYMLINK_JUNCPOINT	0x1
#define SYMLINK_DIRECTORY	0x2

#define WSL_UNK			0x0
#define WSL_LINK		0x1
#define WSL_FIFO		0x2
#define WSL_CHR			0x3
#define WSL_BLK			0x4

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

HANDLE WSL_OpenFileHandle(const wchar_t *Path, int Write, int NoDereference);
HANDLE WSL_CreateFileHandle(const wchar_t *Path);
ssize_t WSL_ReadLinkW(const wchar_t * pathname, wchar_t * buf, size_t bufsiz, int *extinfo);
int WSL_SymLinkW(const wchar_t *target, const wchar_t *linkpath, uint32_t mode, const char *origtarget);
int WSL_MakeSpecialFile(const wchar_t *pathname, int type);
BOOL WSL_SetCsDirectory(const wchar_t *pathname, int enable);
BOOL WSL_SetParameters(const wchar_t *pathname, int nodereference, mode_t mode, uid_t owner, uid_t group, dev_t dev);
BOOL WSL_GetParameters(const wchar_t *pathname, int nodereference, mode_t *mode, uid_t *owner, uid_t *group, dev_t *dev, PLXSS_FILE_EXTENDED_ATTRIBUTES_V1 lxattrb, BOOL *uselxattrb);

#endif
