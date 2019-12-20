#include <windows.h>
#include <ntdef.h>
#include <stdio.h>

ssize_t ReadLinkW(const wchar_t * pathname, wchar_t * buf, size_t bufsiz)
{
	size_t path_len = -1;
	REPARSE_DATA_BUFFER rep_data[REPARSE_DATA_BUFFER_HEADER_SIZE +
				     MAXIMUM_REPARSE_DATA_BUFFER_SIZE];
	DWORD get_size;

	DWORD attr = GetFileAttributesW(pathname);

	if ((attr == INVALID_FILE_ATTRIBUTES) ||
	    !(attr & FILE_ATTRIBUTE_REPARSE_POINT)) {
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
		printf("Could not open file (error %ld\n)", GetLastError());
		goto out;
	}

	if (DeviceIoControl(hFile,
			    FSCTL_GET_REPARSE_POINT,
			    NULL,
			    0,
			    rep_data,
			    sizeof(rep_data),
			    &get_size,
			    NULL) != 0) {
		if (rep_data->ReparseTag == IO_REPARSE_TAG_SYMLINK) {
			if (rep_data->SymbolicLinkReparseBuffer.Flags & 0x0001) {
				printf("symbolic link relatived!\n");
			}
			path_len = rep_data->SymbolicLinkReparseBuffer.SubstituteNameLength;
			path_len = (path_len > bufsiz) ? bufsiz : path_len;
			memcpy(buf, &((BYTE *) rep_data->SymbolicLinkReparseBuffer.PathBuffer)
			       [rep_data->SymbolicLinkReparseBuffer.SubstituteNameOffset],
			       path_len);
			//path[path_len / sizeof(wchar_t)] = 0;
			//wprintf(L"--> %s\n", path);
		} else if (rep_data->ReparseTag == IO_REPARSE_TAG_MOUNT_POINT) {
			path_len = rep_data->MountPointReparseBuffer.SubstituteNameLength;
			path_len = (path_len > bufsiz) ? bufsiz : path_len;
			memcpy(buf, &((BYTE *) rep_data->MountPointReparseBuffer.PathBuffer)
			       [rep_data->MountPointReparseBuffer.SubstituteNameOffset], path_len);
		} else {
			printf("unsupported reparse tag %08X\n", rep_data->ReparseTag);
			if (IsReparseTagNameSurrogate(rep_data->ReparseTag)) {
				path_len = rep_data->ReparseDataLength - 4;
				path_len = (path_len > bufsiz) ? bufsiz : path_len;
				printf("surrogate (%d)\n", rep_data->ReparseDataLength);
				memcpy(buf,
				       &((BYTE *) rep_data->GenericReparseBuffer.DataBuffer)[4],
				       path_len);
				//path[path_len / sizeof(wchar_t)] = 0;
//                      wprintf(L"--> %s\n", path);
//                      printf("--> %s\n", path);
			}
		}
	} else {
		printf("can't read reparse data %ld\n", GetLastError());
	}

 out:
	CloseHandle(hFile);

	return path_len;
}

int SymLinkW(const wchar_t *target, const wchar_t *linkpath)
{
    return -1;
}

#ifdef READLINK_TEST
int main(int argc, char *argv[])
{
    const size_t WCHARBUF = 100;
    wchar_t  pathname[WCHARBUF];
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

#if 0
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
#endif
