#ifdef WIN32
#define _WIN32_WINNT	0x600

#include "config.h"
#include "daemon.h"
#include "winsupport.h"
#include <windows.h>
#include <ntdef.h>
#include <shlwapi.h>
#include <winbase.h>
#include <winternl.h>
#include <ntstatus.h>
#include <stdio.h>
#include <errno.h>
#include "wsl.h"

#define IO_REPARSE_TAG_LX_SYMLINK               (0xA000001DL)
#define IO_REPARSE_TAG_LX_FIFO                  (0x80000024L)
#define IO_REPARSE_TAG_LX_CHR                   (0x80000025L)
#define IO_REPARSE_TAG_LX_BLK                   (0x80000026L)

#ifndef SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
#define SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE	0x2
#endif

HANDLE WSL_OpenFileHandle(const wchar_t *Path, int Write, int NoDereference)
{
    return CreateFileW(Path,
		       Write ? FILE_GENERIC_WRITE : FILE_GENERIC_READ,
		       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		       NULL,
		       OPEN_EXISTING,
		       FILE_FLAG_BACKUP_SEMANTICS | (NoDereference ? FILE_FLAG_OPEN_REPARSE_POINT : 0),
		       NULL);
}

HANDLE WSL_CreateFileHandle(const wchar_t *Path)
{
    return CreateFileW(Path,
		       GENERIC_WRITE,
		       0,
		       NULL,
		       CREATE_NEW,
		       FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
		       NULL);
}

ssize_t WSL_ReadLinkW(const wchar_t *pathname, wchar_t *buf, size_t bufsiz, int *extinfo)
{
    size_t path_len = -1;
    REPARSE_DATA_BUFFER rep_data[REPARSE_DATA_BUFFER_HEADER_SIZE + MAXIMUM_REPARSE_DATA_BUFFER_SIZE];
    DWORD get_size;
    int file_extinfo = WSL_UNK;

    if (extinfo) {
	*extinfo = file_extinfo;
    }

    DWORD attr = GetFileAttributesW(pathname);
    if ((attr == INVALID_FILE_ATTRIBUTES) || !(attr & FILE_ATTRIBUTE_REPARSE_POINT)) {
	return -1;
    }

    HANDLE hFile = WSL_OpenFileHandle(pathname, 0, 1);
    if (hFile == INVALID_HANDLE_VALUE) {
	logmsg(LOG_ERR, "Could not open file (error %ld)", GetLastError());
	return -1;
    } else if (DeviceIoControl(hFile, FSCTL_GET_REPARSE_POINT, NULL, 0, rep_data, sizeof(rep_data), &get_size, NULL)) {
	if (rep_data->ReparseTag == IO_REPARSE_TAG_SYMLINK) {
//	    if (rep_data->SymbolicLinkReparseBuffer.Flags & 0x0001) {
//		logmsg(LOG_INFO, "symbolic link relatived!");
//	    }
	    path_len = rep_data->SymbolicLinkReparseBuffer.SubstituteNameLength;
	    if (buf) {
		path_len = (path_len > bufsiz) ? bufsiz : path_len;
		memcpy(buf, &((BYTE *) rep_data->SymbolicLinkReparseBuffer.PathBuffer)
		       [rep_data->SymbolicLinkReparseBuffer.SubstituteNameOffset], path_len);
	    }
	    file_extinfo = WSL_LINK;
	} else if (rep_data->ReparseTag == IO_REPARSE_TAG_MOUNT_POINT) {
	    path_len = rep_data->MountPointReparseBuffer.SubstituteNameLength;
	    if (buf) {
		path_len = (path_len > bufsiz) ? bufsiz : path_len;
	        memcpy(buf, &((BYTE *) rep_data->MountPointReparseBuffer.PathBuffer)
		       [rep_data->MountPointReparseBuffer.SubstituteNameOffset], path_len);
	    }
	    file_extinfo = WSL_LINK;
	} else if (rep_data->ReparseTag == IO_REPARSE_TAG_LX_SYMLINK) {
	    path_len = MultiByteToWideChar(CP_UTF8,
					   0,
					   &((LPCCH) rep_data->GenericReparseBuffer.DataBuffer)[4],
					   rep_data->ReparseDataLength - 4,
					   buf,
					   buf ? bufsiz : 0);
	    path_len *= sizeof(wchar_t);
	    if (!path_len) {
		logmsg(LOG_WARNING, "%s: MultiByteToWideChar failed", __func__);
	    }
	    file_extinfo = WSL_LINK;
	} else if (rep_data->ReparseTag == IO_REPARSE_TAG_LX_FIFO) {
	    file_extinfo = WSL_FIFO;
	} else if (rep_data->ReparseTag == IO_REPARSE_TAG_LX_CHR) {
	    file_extinfo = WSL_CHR;
	} else if (rep_data->ReparseTag == IO_REPARSE_TAG_LX_BLK) {
	    file_extinfo = WSL_BLK;
	} else {
	    logmsg(LOG_WARNING, "unsupported reparse tag %08X (%d bytes)", (unsigned int)rep_data->ReparseTag, rep_data->ReparseDataLength);
	    errno = EINVAL;
	}
    } else {
	logmsg(LOG_ERR, "can't read reparse data %ld", GetLastError());
	errno = EINVAL;
    }

    if (extinfo) {
	*extinfo = file_extinfo;
    }

    CloseHandle(hFile);

    return path_len;
}

int WSL_SymLinkW(const wchar_t *target, const wchar_t *linkpath, uint32_t type, const char *origtarget)
{
    int ret = -1;

    if (type & SYMLINK_JUNCPOINT) {
	HANDLE hFile = WSL_CreateFileHandle(linkpath);
	if (hFile == INVALID_HANDLE_VALUE) {
	    logmsg(LOG_ERR, "%s: Could not open file (error %ld)", __func__, GetLastError());
	    errno = EACCES;
	} else {
	    DWORD returned_bytes;
	    REPARSE_DATA_BUFFER *rep_data;
	    int rep_length = REPARSE_DATA_BUFFER_HEADER_SIZE +
		sizeof(rep_data->GenericReparseBuffer) - sizeof(rep_data->GenericReparseBuffer.DataBuffer) +
		4 + strlen(origtarget);
	    rep_data = alloca(rep_length);
	    rep_data->ReparseTag = IO_REPARSE_TAG_LX_SYMLINK;
	    rep_data->ReparseDataLength = 4 + strlen(origtarget);
	    *((DWORD *) &rep_data->GenericReparseBuffer.DataBuffer[0]) = 0x00000002;
	    memcpy(&(rep_data->GenericReparseBuffer.DataBuffer)[4], origtarget, strlen(origtarget));
	
	    if (DeviceIoControl(hFile, FSCTL_SET_REPARSE_POINT, rep_data, rep_length, NULL, 0, &returned_bytes, NULL)) {
		ret = 0;
	    } else {
		logmsg(LOG_ERR, "%s: DeviceIoControl (error %ld)", __func__, GetLastError());
		errno = EIO;
	    }

	    CloseHandle(hFile);
	}
    } else {
	if (CreateSymbolicLinkW(linkpath,
				target,
				SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE |
				    ((type & SYMLINK_DIRECTORY)?SYMBOLIC_LINK_FLAG_DIRECTORY:0))) {
	    ret = 0;
	} else {
	    errno = EIO;
	}
    }

    return ret;
}

int WSL_MakeSpecialFile(const wchar_t *pathname, int type)
{
    int ret = -1;

    if (type < WSL_FIFO && type > WSL_BLK) {
	errno = EINVAL;
	return -1;
    }

    HANDLE hFile = WSL_CreateFileHandle(pathname);
    if (hFile == INVALID_HANDLE_VALUE) {
	logmsg(LOG_ERR, "%s: Could not open file (error %ld)", __func__, GetLastError());
	errno = EACCES;
    } else {
	DWORD returned_bytes;
	REPARSE_DATA_BUFFER *rep_data;
	int rep_length = REPARSE_DATA_BUFFER_HEADER_SIZE +
	    sizeof(rep_data->GenericReparseBuffer) - sizeof(rep_data->GenericReparseBuffer.DataBuffer);
	rep_data = alloca(rep_length);
	switch(type) {
	case WSL_CHR:  rep_data->ReparseTag = IO_REPARSE_TAG_LX_CHR; break;
	case WSL_BLK:  rep_data->ReparseTag = IO_REPARSE_TAG_LX_BLK; break;
	case WSL_FIFO: rep_data->ReparseTag = IO_REPARSE_TAG_LX_FIFO; break;
	default:       rep_data->ReparseTag = 0; break;
	}
	if (rep_data->ReparseTag) {
	    rep_data->ReparseDataLength = 0;
	
	    if (DeviceIoControl(hFile, FSCTL_SET_REPARSE_POINT, rep_data, rep_length, NULL, 0, &returned_bytes, NULL)) {
		ret = 0;
	    } else {
		logmsg(LOG_ERR, "%s: DeviceIoControl (error %ld)", __func__, GetLastError());
		errno = EIO;
	    }
	}
	CloseHandle(hFile);
    }

    return ret;
}

#ifndef FILE_CS_FLAG_CASE_SENSITIVE_DIR
#define FILE_CS_FLAG_CASE_SENSITIVE_DIR 0x00000001
#endif
#define FileCaseSensitiveInformation (FILE_INFORMATION_CLASS)71
typedef struct {
    ULONG Flags;
} FILE_CASE_SENSITIVE_INFORMATION, *PFILE_CASE_SENSITIVE_INFORMATION;

BOOL WSL_SetCsDirectory(const wchar_t *pathname, int enable)
{
    BOOL ret = FALSE;
    HANDLE hFile = WSL_OpenFileHandle(pathname, 1, 1);
    if (hFile == INVALID_HANDLE_VALUE) {
	logmsg(LOG_ERR, "%s: Could not open file (error %ld)", __func__, GetLastError());
	return FALSE;
    }

    IO_STATUS_BLOCK iob;
    FILE_CASE_SENSITIVE_INFORMATION info;
    NTSTATUS stat = NtQueryInformationFile(hFile, &iob, &info, sizeof(info), FileCaseSensitiveInformation);
    if (!stat && ((enable && (info.Flags & FILE_CS_FLAG_CASE_SENSITIVE_DIR)) ||
		  (!enable && !(info.Flags & FILE_CS_FLAG_CASE_SENSITIVE_DIR)))){
	logmsg(LOG_INFO, "Case sensitivite directory already %s", enable ? "enabled" : "disabled");
	goto out;
    }

    info.Flags = enable ? FILE_CS_FLAG_CASE_SENSITIVE_DIR : 0;
    stat = NtSetInformationFile(hFile, &iob, &info, sizeof(info), FileCaseSensitiveInformation);
    if (!stat) {
	ret = TRUE;
    } else {
	if (stat == STATUS_ACCESS_DENIED) {
	    logmsg(LOG_ERR, "%s: Cannot set case sensitivite directory - access denied", __func__);
	} else {
	    logmsg(LOG_ERR, "%s: SetFileInformationByHandle %ld", stat);
	}
    }

out:
    CloseHandle(hFile);
    return ret;
}

NTSYSAPI NTSTATUS NTAPI
NtQueryEaFile( /*IN*/ HANDLE FileHandle,
	      /*OUT*/ PIO_STATUS_BLOCK IoStatusBlock,
	      /*OUT*/ PVOID Buffer,
	       /*IN*/ ULONG Length,
	       /*IN*/ BOOLEAN ReturnSingleEntry,
	       /*IN*/ PVOID EaList /*OPTIONAL*/,
	       /*IN*/ ULONG EaListLength, /*IN*/ PULONG EaIndex /*OPTIONAL*/, /*IN*/ BOOLEAN RestartScan);

NTSYSAPI NTSTATUS NTAPI
NtSetEaFile( /*IN*/ HANDLE FileHandle,
	    /*OUT*/ PIO_STATUS_BLOCK IoStatusBlock,
	    /*OUT*/ PVOID Buffer,
	     /*IN*/ ULONG Length);

static struct EaList *GetEaList(HANDLE hFile)
{
    NTSTATUS Status = 0;
    IO_STATUS_BLOCK IoStatusBlock = { 0 };
    CHAR Buffer[MAX_LIST_LEN];
    PFILE_FULL_EA_INFORMATION EaBuffer;
    BOOLEAN RestartScan = TRUE;
    struct EaList *Result = (struct EaList *)malloc(sizeof(struct EaList));

    do {
	EaBuffer = (PFILE_FULL_EA_INFORMATION) Buffer;

	Status = NtQueryEaFile(hFile,
			       &IoStatusBlock,
			       EaBuffer,
			       MAX_LIST_LEN,
			       FALSE,
			       NULL,
			       0,
			       NULL,
			       RestartScan);
	if (Status != STATUS_SUCCESS && Status != STATUS_BUFFER_OVERFLOW) {
	    free(Result);
	    return NULL;
	}

	while (EaBuffer) {
	    strcpy_s(Result->List[Result->ListSize].Name, MAX_EA_VALUE, EaBuffer->EaName);
	    memcpy_s(Result->List[Result->ListSize].Value, MAX_EA_VALUE,
		     EaBuffer->EaName + EaBuffer->EaNameLength + 1, EaBuffer->EaValueLength);
	    Result->List[Result->ListSize].ValueLength = EaBuffer->EaValueLength;
	    Result->ListSize++;

	    if (EaBuffer->NextEntryOffset == 0) {
		break;
	    }

	    EaBuffer = (PFILE_FULL_EA_INFORMATION) ((PCHAR) EaBuffer + EaBuffer->NextEntryOffset);
	}

	RestartScan = FALSE;
    }
    while (Status == STATUS_BUFFER_OVERFLOW);

    return Result;
}

static ULONG AddToEaBuffer(PFILE_FULL_EA_INFORMATION EaBuffer, PSTR EaName, PSTR EaValue, ULONG32 EaValueLength)
{
    ULONG EaNameLength =(ULONG)(strlen(EaName) + 1);
    memcpy_s(EaBuffer->EaName, EaNameLength, EaName, EaNameLength);
    EaBuffer->EaNameLength = (UCHAR) EaNameLength - 1;
    if (EaValue == NULL) {
	EaBuffer->EaValueLength = 0;
    } else {
	memcpy_s(EaBuffer->EaName + EaBuffer->EaNameLength + 1, EaValueLength, EaValue, EaValueLength);
	EaBuffer->EaValueLength = EaValueLength;
    }
    EaBuffer->Flags = 0;
    return EaBuffer->EaNameLength + 1 + EaBuffer->EaValueLength;
}

BOOL WSL_SetParameters(const wchar_t *pathname, int nodereference, mode_t mode, uid_t owner, uid_t group, dev_t dev)
{
    HANDLE hFile;
    CHAR Buffer[MAX_FULLEA] = { 0 };
    IO_STATUS_BLOCK IoStatusBlock = { 0 };
    PFILE_FULL_EA_INFORMATION EaBuffer = NULL;
    ULONG EaLength = 0;

    hFile = WSL_OpenFileHandle(pathname, 1, nodereference);
    if (hFile == NULL) {
	return FALSE;
    }

    EaBuffer = (PFILE_FULL_EA_INFORMATION) Buffer;

    if ((int)owner != -1) {
	DWORD val = owner;
	EaBuffer->NextEntryOffset = AddToEaBuffer(EaBuffer, "$LXUID", (PSTR)&val, sizeof(val));
	EaBuffer->NextEntryOffset += FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName);
	EaBuffer->NextEntryOffset = (EaBuffer->NextEntryOffset + 3) & ~3;
	EaLength += EaBuffer->NextEntryOffset;
    }

    if ((int)group != -1) {
	DWORD val = group;
	EaBuffer = (PFILE_FULL_EA_INFORMATION)((PCHAR) EaBuffer + EaBuffer->NextEntryOffset);
	EaBuffer->NextEntryOffset = AddToEaBuffer(EaBuffer, "$LXGID", (PSTR)&val, sizeof(val));
	EaBuffer->NextEntryOffset += FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName);
	EaBuffer->NextEntryOffset = (EaBuffer->NextEntryOffset + 3) & ~3;
	EaLength += EaBuffer->NextEntryOffset;
    }

    if (mode != (mode_t)-1) {
	DWORD val = mode;
	EaBuffer = (PFILE_FULL_EA_INFORMATION)((PCHAR) EaBuffer + EaBuffer->NextEntryOffset);
	EaBuffer->NextEntryOffset = AddToEaBuffer(EaBuffer, "$LXMOD", (PSTR)&val, sizeof(val));
	EaBuffer->NextEntryOffset += FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName);
	EaBuffer->NextEntryOffset = (EaBuffer->NextEntryOffset + 3) & ~3;
	EaLength += EaBuffer->NextEntryOffset;
    }

    if ((int)dev != -1) {
	DWORD val[2] = { (dev >> 8) & 0xFF, dev & 0xFF };
	EaBuffer = (PFILE_FULL_EA_INFORMATION)((PCHAR) EaBuffer + EaBuffer->NextEntryOffset);
	EaBuffer->NextEntryOffset = AddToEaBuffer(EaBuffer, "$LXDEV", (PSTR)&val, sizeof(val));
	EaBuffer->NextEntryOffset += FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName);
	EaBuffer->NextEntryOffset = (EaBuffer->NextEntryOffset + 3) & ~3;
	EaLength += EaBuffer->NextEntryOffset;
    }

    EaBuffer->NextEntryOffset = 0;

    if (EaLength) {
	NTSTATUS status;
	if ((status = NtSetEaFile(hFile, &IoStatusBlock, (PFILE_FULL_EA_INFORMATION) Buffer, EaLength))) {
	    if (status == STATUS_EA_LIST_INCONSISTENT) {
		logmsg(LOG_ERR, "bad format of list");
	    }
	    logmsg(LOG_ERR, "NtSetEaFile() error %ld", GetLastError());
	    CloseHandle(hFile);
	    return FALSE;
	}
    }

    CloseHandle(hFile);

    return TRUE;
}

BOOL WSL_GetParameters(const wchar_t *pathname, int nodereference, mode_t *mode, uid_t *owner, uid_t *group, dev_t *dev, PLXSS_FILE_EXTENDED_ATTRIBUTES_V1 lxattrb, BOOL *uselxattrb)
{
    struct EaList *eaList;
    unsigned int i;
    BOOL status = FALSE;

    if (mode) {
	*mode = -1;
    }
    if (owner) {
	*owner = -1;
    }
    if (group) {
	*group = -1;
    }
    if (dev) {
	*dev = -1;
    }
    if (uselxattrb) {
	*uselxattrb = FALSE;
    }

    HANDLE hFile = WSL_OpenFileHandle(pathname, 0, nodereference);
    if (hFile == NULL) {
	return FALSE;
    }

    eaList = GetEaList(hFile);

    CloseHandle(hFile);

    if (!eaList) {
	return FALSE;
    }

    for (i = 0; i < eaList->ListSize; i++) {
	if (!strcmp(eaList->List[i].Name, "$LXMOD") && eaList->List[i].ValueLength == 4) {
	    if (mode) {
		*mode = *((uint32_t *) eaList->List[i].Value);
		status = TRUE;
	    }
	} else if (!strcmp(eaList->List[i].Name, "$LXUID") && eaList->List[i].ValueLength == 4) {
	    if (owner) {
		*owner = *((uint32_t *) eaList->List[i].Value);
		status = TRUE;
	    }
	} else if (!strcmp(eaList->List[i].Name, "$LXGID") && eaList->List[i].ValueLength == 4) {
	    if (group) {
		*group = *((uint32_t *) eaList->List[i].Value);
		status = TRUE;
	    }
	} else if (!strcmp(eaList->List[i].Name, "$LXDEV") && eaList->List[i].ValueLength == 8) {
	    if (dev) {
		uint32_t *ptr = (uint32_t *) eaList->List[i].Value;
		*dev = (ptr[0] << 8) | ptr[1];
		status = TRUE;
	    }
	} else if (!strcmp(eaList->List[i].Name, "$LXATTRB") && eaList->List[i].ValueLength == sizeof(LXSS_FILE_EXTENDED_ATTRIBUTES_V1)) {
	    if (uselxattrb) {
		*uselxattrb = TRUE;
		status = TRUE;
	    }
	    if (lxattrb) {
		memcpy(lxattrb, eaList->List[i].Value, sizeof(LXSS_FILE_EXTENDED_ATTRIBUTES_V1));
		status = TRUE;
	    }
	}
    }

    free(eaList);

    return status;
}

#endif /* WIN32 */
