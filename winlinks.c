#ifdef WIN32
#define _WIN32_WINNT	0x600

#include "config.h"
#include "daemon.h"
#include "winsupport.h"
#include <windows.h>
#include <ntdef.h>
#include <shlwapi.h>
#include <winbase.h>
#include <stdio.h>
#include <errno.h>
#include "winlinks.h"

#define IO_REPARSE_TAG_LX_SYMLINK               (0xA000001DL)
#define IO_REPARSE_TAG_LX_FIFO                  (0x80000024L)
#define IO_REPARSE_TAG_LX_CHR                   (0x80000025L)
#define IO_REPARSE_TAG_LX_BLK                   (0x80000026L)

ssize_t ReadLinkW(const wchar_t * pathname, wchar_t * buf, size_t bufsiz, int *extinfo)
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

    HANDLE hFile = CreateFileW(pathname,
			       FILE_READ_EA,
			       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			       NULL,
			       OPEN_EXISTING,
			       FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
			       NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
	logmsg(LOG_ERR, "Could not open file (error %ld)", GetLastError());
	goto out;
    }

    if (DeviceIoControl(hFile, FSCTL_GET_REPARSE_POINT, NULL, 0, rep_data, sizeof(rep_data), &get_size, NULL) != 0) {
	if (rep_data->ReparseTag == IO_REPARSE_TAG_SYMLINK) {
//	    if (rep_data->SymbolicLinkReparseBuffer.Flags & 0x0001) {
//		logmsg(LOG_INFO, "symbolic link relatived!");
//	    }
	    path_len = rep_data->SymbolicLinkReparseBuffer.SubstituteNameLength;
	    path_len = (path_len > bufsiz) ? bufsiz : path_len;
	    memcpy(buf, &((BYTE *) rep_data->SymbolicLinkReparseBuffer.PathBuffer)
		   [rep_data->SymbolicLinkReparseBuffer.SubstituteNameOffset], path_len);
	} else if (rep_data->ReparseTag == IO_REPARSE_TAG_MOUNT_POINT) {
	    path_len = rep_data->MountPointReparseBuffer.SubstituteNameLength;
	    path_len = (path_len > bufsiz) ? bufsiz : path_len;
	    memcpy(buf, &((BYTE *) rep_data->MountPointReparseBuffer.PathBuffer)
		   [rep_data->MountPointReparseBuffer.SubstituteNameOffset], path_len);
	} else if (rep_data->ReparseTag == IO_REPARSE_TAG_LX_SYMLINK) {
	    path_len = MultiByteToWideChar(CP_UTF8,
					   0,
					   &((LPCCH) rep_data->GenericReparseBuffer.DataBuffer)[4],
					   rep_data->ReparseDataLength - 4,
					   buf,
					   bufsiz);
	    path_len *= sizeof(wchar_t);
	    if (!path_len) {
		logmsg(LOG_WARNING, "%s: MultiByteToWideChar failed", __func__);
//		errno = EINVAL;
//		path_len = -1;
	    }
	    file_extinfo = WSL_LINK;
	} else if (rep_data->ReparseTag == IO_REPARSE_TAG_LX_FIFO) {
	    file_extinfo = WSL_FIFO;
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

 out:
    CloseHandle(hFile);

    return path_len;
}

int SymLinkW(const wchar_t * target, const wchar_t * linkpath, uint32_t mode, const char *origtarget)
{
    int ret = -1;

    if (mode & SYMLINK_JUNCPOINT) {
	HANDLE hFile = CreateFileW(linkpath,
				   GENERIC_WRITE,
				   0,
				   NULL,
				   CREATE_NEW,
				   FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
				   NULL);

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
				    ((mode & SYMLINK_DIRECTORY)?SYMBOLIC_LINK_FLAG_DIRECTORY:0))) {
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

    HANDLE hFile = CreateFileW(pathname,
			       GENERIC_WRITE,
			       0,
			       NULL,
			       CREATE_NEW,
			       FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
			       NULL);

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
	case WSL_CHAR: rep_data->ReparseTag = IO_REPARSE_TAG_LX_CHR; break;
	case WSL_BLK:  rep_data->ReparseTag = IO_REPARSE_TAG_LX_BLK; break;
	default:       rep_data->ReparseTag = IO_REPARSE_TAG_LX_FIFO; break;
	}
	rep_data->ReparseDataLength = 0;
	
	if (DeviceIoControl(hFile, FSCTL_SET_REPARSE_POINT, rep_data, rep_length, NULL, 0, &returned_bytes, NULL)) {
	    ret = 0;
	} else {
	    logmsg(LOG_ERR, "%s: DeviceIoControl (error %ld)", __func__, GetLastError());
	    errno = EIO;
	}

	CloseHandle(hFile);
    }

    return ret;
}

typedef enum _XFILE_INFO_BY_HANDLE_CLASS {
    _FileBasicInfo,
    _FileStandardInfo,
    _FileNameInfo,
    _FileRenameInfo,
    _FileDispositionInfo,
    _FileAllocationInfo,
    _FileEndOfFileInfo,
    _FileStreamInfo,
    _FileCompressionInfo,
    _FileAttributeTagInfo,
    _FileIdBothDirectoryInfo,
    _FileIdBothDirectoryRestartInfo,
    _FileIoPriorityHintInfo,
    _FileRemoteProtocolInfo,
    _FileFullDirectoryInfo,
    _FileFullDirectoryRestartInfo,
    FileStorageInfo,
    FileAlignmentInfo,
    FileIdInfo,
    FileIdExtdDirectoryInfo,
    FileIdExtdDirectoryRestartInfo,
    FileDispositionInfoEx,
    FileRenameInfoEx,
    FileCaseSensitiveInfo,
    FileNormalizedNameInfo,
    _MaximumFileInfoByHandleClass
} XFILE_INFO_BY_HANDLE_CLASS, *PXFILE_INFO_BY_HANDLE_CLASS;

typedef struct _FILE_CASE_SENSITIVE_INFO {
    ULONG Flags;
} FILE_CASE_SENSITIVE_INFO, *PFILE_CASE_SENSITIVE_INFO;

#define FILE_CS_FLAG_CASE_SENSITIVE_DIR     0x00000001

BOOL WSL_SetCsDirectory(const wchar_t *pathname, int enable)
{
    BOOL status = FALSE;
    HANDLE hFile = CreateFileW(pathname,
			       FILE_WRITE_ATTRIBUTES,
			       FILE_SHARE_READ | FILE_SHARE_WRITE,
			       NULL,
			       OPEN_EXISTING,
			       FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
			       NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
	logmsg(LOG_ERR, "%s: Could not open file (error %ld)", __func__, GetLastError());
	return FALSE;
    }

    FILE_CASE_SENSITIVE_INFO file_cs = { enable?FILE_CS_FLAG_CASE_SENSITIVE_DIR:0 };

    if (SetFileInformationByHandle(hFile, FileCaseSensitiveInfo, &file_cs, sizeof(file_cs))) {
	status = TRUE;
    } else {
	logmsg(LOG_ERR, "%s: SetFileInformationByHandle %ld", GetLastError());
    }

    CloseHandle(hFile);
    return status;
}

#ifdef READLINK_TEST
int main(int argc, char *argv[])
{
    const size_t WCHARBUF = 100;
    wchar_t pathname[WCHARBUF];
    MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, argv[1], -1, pathname, WCHARBUF);

    if (argc != 2) {
	printf("ERROR:\tIncorrect number of arguments\n\n");
	printf("%s <file_name>\n", argv[0]);
	return 1;
    }

    wchar_t path[256];

    size_t path_len = ReadLinkW(pathname, path, sizeof(path));

    if (path_len != -1) {
	path[path_len / sizeof(wchar_t)] = 0;
	wprintf(L"%s -> %s\n", pathname, path);
    } else {
	printf("Not a symlink\n");
    }

    return 0;
}
#endif

/*
DWORD attr = GetFileAttributes(argv[1]);
if (attr == INVALID_FILE_ATTRIBUTES) {
    if (GetLastError() == ERROR_FILE_NOT_FOUND) {
	printf("File not found\n");
	return 1;
    }
    printf("Error!\n");
}

if (attr & FILE_ATTRIBUTE_REPARSE_POINT) {
    printf("symlink\n");
}
 */
#endif /* WIN32 */
