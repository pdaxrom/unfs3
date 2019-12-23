/*

	Small library to read and write NTFS extended attributes.
	See ntfsea.py for a helper class to use it from Python.

	Part of the https://github.com/RoliSoft/WSL-Distribution-Switcher
	project, licensed under the MIT license.

*/

#ifdef WIN32
#define _WIN32_WINNT	0x600

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include "config.h"
#include "daemon.h"
#include <winternl.h>
#include <ntstatus.h>
#include <tchar.h>
#include <stdlib.h>
#include <stdio.h>

#include <inttypes.h>
#include <sys/types.h>

#include "winsupport.h"
#include "ntfsea.h"

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

/*!
 * Opens the requested file for reading or writing.
 *
 * \param DosFileName Path to the file in wide-string format.
 * \param Write       Value indicating whether to open for writing.
 * \param EaBuffer    Pointer to allocated memory for the extended attributes information.
 * \param EaLength    Length of the extended attributes information.
 *
 * \return Handle to the opened file pointer or NULL on failure.
 */
HANDLE GetFileHandle(PWSTR DosFileName, BOOL Write, PFILE_FULL_EA_INFORMATION EaBuffer, ULONG EaLength)
{
    UNICODE_STRING FileName;
    OBJECT_ATTRIBUTES ObjectAttributes;
    ACCESS_MASK DesiredAccess = FILE_GENERIC_READ;
    HANDLE FileHandle;
    IO_STATUS_BLOCK IoStatusBlock;

    if (Write) {
	DesiredAccess |= FILE_GENERIC_WRITE;
    }

    if (!RtlDosPathNameToNtPathName_U(DosFileName, &FileName, NULL, NULL)) {
	return NULL;
    }

    InitializeObjectAttributes(&ObjectAttributes, &FileName, 0, NULL, NULL);

    if (NtCreateFile(&FileHandle,
		     DesiredAccess,
		     &ObjectAttributes,
		     &IoStatusBlock,
		     NULL,
		     0,
		     FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		     Write ? FILE_OPEN_IF : FILE_OPEN,
		     0,
		     EaBuffer,
		     EaLength)) {
	return NULL;
    }

    return FileHandle;
}

/*!
 * Fetches the list of extended attributes available on the requested file.
 *
 * \param FileName Path to the file in wide-string format.
 *
 * \return List of extended attributes or NULL on error.
 */
DLL_EXPORT struct EaList *GetEaList(PWSTR FileName)
{
    NTSTATUS Status = 0;
    HANDLE FileHandle;
    IO_STATUS_BLOCK IoStatusBlock = { 0 };
    CHAR Buffer[MAX_LIST_LEN];
    PFILE_FULL_EA_INFORMATION EaBuffer;
    BOOLEAN RestartScan = TRUE;
    struct EaList *Result = (struct EaList *)malloc(sizeof(struct EaList));

    FileHandle = GetFileHandle(FileName, FALSE, NULL, 0);
    if (FileHandle == NULL) {
	free(Result);
	return NULL;
    }

    do {
	EaBuffer = (PFILE_FULL_EA_INFORMATION) Buffer;

	Status = NtQueryEaFile(FileHandle,
			       &IoStatusBlock,
			       EaBuffer,
			       MAX_LIST_LEN,
			       FALSE,
			       NULL,
			       0,
			       NULL,
			       RestartScan);
	if (Status != STATUS_SUCCESS && Status != STATUS_BUFFER_OVERFLOW) {
	    NtClose(FileHandle);
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

    NtClose(FileHandle);

    return Result;
}

/*!
 * Fetches the specified extended attribute and its value from the requested file.
 *
 * \param FileName Path to the file in wide-string format.
 * \param EaName   Name of the extended attribute in a null-terminated string.
 *
 * \return Extended attribute information or NULL on error.
 */
DLL_EXPORT struct Ea *GetEa(PWSTR FileName, PSTR EaName)
{
    NTSTATUS Status = 0;
    HANDLE FileHandle;
    IO_STATUS_BLOCK IoStatusBlock = { 0 };
    CHAR GetBuffer[MAX_LIST_LEN] = { 0 };
    CHAR FullBuffer[MAX_LIST_LEN] = { 0 };
    PFILE_GET_EA_INFORMATION EaList = (PFILE_GET_EA_INFORMATION) GetBuffer;
    PFILE_GET_EA_INFORMATION EaQuery = EaList;
    PFILE_FULL_EA_INFORMATION EaBuffer = (PFILE_FULL_EA_INFORMATION) FullBuffer;
    ULONG EaListLength = 0;
    ULONG EaNameLength = strlen(EaName);
    struct Ea *Result = (struct Ea *)malloc(sizeof(struct Ea));

    FileHandle = GetFileHandle(FileName, FALSE, NULL, 0);
    if (FileHandle == NULL) {
	free(Result);
	return NULL;
    }

    EaNameLength = (ULONG) ((EaNameLength + 1) * sizeof(CHAR));
    memcpy_s(EaQuery->EaName, EaNameLength, EaName, EaNameLength);
    EaQuery->EaNameLength = (UCHAR) EaNameLength - sizeof(CHAR);

    EaQuery->NextEntryOffset = FIELD_OFFSET(FILE_GET_EA_INFORMATION, EaName) + EaQuery->EaNameLength + sizeof(CHAR);
    EaListLength += EaQuery->NextEntryOffset;
    EaQuery->NextEntryOffset = 0;

    EaQuery = (PFILE_GET_EA_INFORMATION) ((PCHAR) EaQuery + EaQuery->NextEntryOffset);

    Status = NtQueryEaFile(FileHandle,
			   &IoStatusBlock,
			   EaBuffer,
			   MAX_FULLEA,
			   FALSE,
			   EaList,
			   EaListLength,
			   NULL,
			   TRUE);
    if (Status != STATUS_SUCCESS) {
	NtClose(FileHandle);
	free(Result);
	return NULL;
    }

    if (EaBuffer && EaBuffer->EaValueLength > 0) {
	strcpy_s(Result->Name, MAX_EA_VALUE, EaBuffer->EaName);
	memcpy_s(Result->Value, MAX_EA_VALUE, EaBuffer->EaName + EaBuffer->EaNameLength + 1, EaBuffer->EaValueLength);
	Result->ValueLength = EaBuffer->EaValueLength;
    } else {
	free(Result);
	Result = NULL;
    }

    NtClose(FileHandle);

    return Result;
}

/*!
 * Writes the specified extended attribute and its value to the requested file.
 *
 * \param FileName      Path to the file in wide-string format.
 * \param EaName        Name of the extended attribute in a null-terminated string.
 * \param EaValue       Value of the extended attribute.
 * \param EaValueLength Length of the extended attribute value.
 *
 * \return Number of bytes written (should match EaValueLength) or -1 on failure.
 */
DLL_EXPORT LONG32 WriteEa(PWSTR FileName, PSTR EaName, PSTR EaValue, ULONG32 EaValueLength)
{
    HANDLE FileHandle;
    ULONG EaNameLength = strlen(EaName);
    CHAR Buffer[MAX_FULLEA] = { 0 };
    IO_STATUS_BLOCK IoStatusBlock = { 0 };
    PFILE_FULL_EA_INFORMATION EaBuffer = NULL;
    ULONG EaLength = 0;

    FileHandle = GetFileHandle(FileName, TRUE, EaBuffer, EaLength);
    if (FileHandle == NULL) {
	return -1;
    }

    EaBuffer = (PFILE_FULL_EA_INFORMATION) Buffer;
    EaBuffer->NextEntryOffset = 0;
    EaBuffer->Flags = 0;

    EaNameLength = (ULONG) ((EaNameLength + 1) * sizeof(CHAR));
    memcpy_s(EaBuffer->EaName, EaNameLength, EaName, EaNameLength);
    EaBuffer->EaNameLength = (UCHAR) EaNameLength - sizeof(CHAR);

    if (EaValue == NULL) {
	EaBuffer->EaValueLength = 0;
    } else {
	EaValueLength = (ULONG) ((EaValueLength + 1) * sizeof(CHAR));
	memcpy_s(EaBuffer->EaName + EaBuffer->EaNameLength + sizeof(CHAR), EaValueLength, EaValue, EaValueLength);
	EaBuffer->EaValueLength = EaValueLength - sizeof(CHAR);
    }

    EaLength = FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName) + EaBuffer->EaNameLength +
	       sizeof(CHAR) + EaBuffer->EaValueLength;

    if (NtSetEaFile(FileHandle, &IoStatusBlock, EaBuffer, EaLength)) {
	NtClose(FileHandle);
	return -1;
    }

    NtClose(FileHandle);

    return EaBuffer->EaValueLength;
}

BOOL WSL_GetMode(PWSTR FileName, mode_t * Mode)
{
    struct Ea *ea = GetEa(FileName, "$LXMOD");
    if (!ea) {
	return FALSE;
    }
    uint32_t *ptr = (uint32_t *) ea->Value;
    *Mode = *ptr;
    free(ea);
    return TRUE;
}

BOOL WSL_SetMode(PWSTR FileName, mode_t Mode)
{
    uint32_t val = Mode;
    if (WriteEa(FileName, "$LXMOD", (PSTR) & val, 4) == -1) {
	return FALSE;
    }
    return TRUE;
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

BOOL WSL_Chown(PWSTR FileName, uid_t owner, uid_t group)
{
    HANDLE FileHandle;
    CHAR Buffer[MAX_FULLEA] = { 0 };
    IO_STATUS_BLOCK IoStatusBlock = { 0 };
    PFILE_FULL_EA_INFORMATION EaBuffer = NULL;
    ULONG EaLength = 0;

    FileHandle = GetFileHandle(FileName, TRUE, EaBuffer, EaLength);
    if (FileHandle == NULL) {
	return FALSE;
    }

    EaBuffer = (PFILE_FULL_EA_INFORMATION) Buffer;

    if ((int)owner != -1) {
	DWORD val = owner;
	EaLength = AddToEaBuffer(EaBuffer, "$LXUID", (PSTR)&val, sizeof(val));
	EaBuffer->NextEntryOffset = 0;
	EaLength += FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName);
    }

    if ((int)group != -1) {
	DWORD val = group;
	EaLength = (EaLength + 3) & ~3;
	EaBuffer->NextEntryOffset = EaLength;
	EaBuffer = (PFILE_FULL_EA_INFORMATION)((PCHAR) EaBuffer + EaBuffer->NextEntryOffset);
	EaLength += AddToEaBuffer(EaBuffer, "$LXGID", (PSTR)&val, sizeof(val));
	EaBuffer->NextEntryOffset = 0;
	EaLength += FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName);
    }

    if (EaLength) {
	NTSTATUS status;
	if ((status = NtSetEaFile(FileHandle, &IoStatusBlock, (PFILE_FULL_EA_INFORMATION) Buffer, EaLength))) {
	//    if (status == STATUS_EA_LIST_INCONSISTENT) {
	//	logmsg(LOG_ERR, "bad format of list");
	//    }
	    logmsg(LOG_ERR, "NtSetEaFile() error %ld", GetLastError());
	    NtClose(FileHandle);
	    return FALSE;
	}
    }

    NtClose(FileHandle);

    return TRUE;
}

BOOL WSL_GetParameters(PWSTR FileName, mode_t *mode, uid_t *owner, uid_t *group, PLXSS_FILE_EXTENDED_ATTRIBUTES_V1 lxattrb, BOOL *uselxattrb)
{
    struct EaList *eaList;
    unsigned int i;
    BOOL status = FALSE;

    *mode = -1;
    *owner = -1;
    *group = -1;
    *uselxattrb = FALSE;

    eaList = GetEaList(FileName);

    if (!eaList) {
	return FALSE;
    }

    for (i = 0; i < eaList->ListSize; i++) {
	if (!strcmp(eaList->List[i].Name, "$LXMOD") && eaList->List[i].ValueLength == 4) {
	    *mode = *((uint32_t *) eaList->List[i].Value);
	    status = TRUE;
	} else if (!strcmp(eaList->List[i].Name, "$LXUID") && eaList->List[i].ValueLength == 4) {
	    *owner = *((uint32_t *) eaList->List[i].Value);
	    status = TRUE;
	} else if (!strcmp(eaList->List[i].Name, "$LXGID") && eaList->List[i].ValueLength == 4) {
	    *group = *((uint32_t *) eaList->List[i].Value);
	    status = TRUE;
	} else if (!strcmp(eaList->List[i].Name, "$LXATTRB") && eaList->List[i].ValueLength == sizeof(LXSS_FILE_EXTENDED_ATTRIBUTES_V1)) {
	    *uselxattrb = TRUE;
	    memcpy(lxattrb, eaList->List[i].Value, sizeof(LXSS_FILE_EXTENDED_ATTRIBUTES_V1));
	    status = TRUE;
	}
    }

    free(eaList);

    return status;
}

#endif
