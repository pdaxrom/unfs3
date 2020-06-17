
/*
 * unfs3 Windows compatibility layer
 * Copyright 2006 Peter Åstrand <astrand@cendio.se> for Cendio AB
 * see file LICENSE for license details
 */

#ifdef WIN32
#define _WIN32_WINNT	0x600

#include "config.h"

#include <errno.h>
#include <stdio.h>
#include "winsupport.h"
#include "Config/exports.h"
#include "daemon.h"
#include <assert.h>
#include <windows.h>
#include <wincrypt.h>
#include <shlwapi.h>
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <direct.h>
#include <dirent.h>
#include <locale.h>
#include "wsl.h"

#define MAX_NUM_DRIVES 26
#define FT70SEC 11644473600LL	       /* seconds between 1601-01-01 and
				          1970-01-01 */

#define wsizeof(x) (sizeof(x)/sizeof(wchar_t))

typedef struct _fdname {
    int fd;
    char *name;
    struct _fdname *next;
} fdname;

static fdname *fdnames = NULL;

static uid_t fake_euid = 0;
static uid_t fake_egid = 0;

static char *get_fdname(int fd)
{
    fdname *fn;

    for (fn = fdnames; fn; fn = fn->next) {
	if (fn->fd == fd) {
	    return fn->name;
	    break;
	}
    }

    assert(0);
    return NULL;
}

static int add_fdname(int fd, const char *name)
{
    fdname *fn;

    fn = malloc(sizeof(fdname));
    if (!fn) {
	logmsg(LOG_CRIT, "add_mount: Unable to allocate memory");
	return -1;
    }

    fn->fd = fd;
    fn->name = strdup(name);
    fn->next = fdnames;
    fdnames = fn;

    return fd;
}

static void remove_fdname(int fd)
{
    fdname *fn, **prevnext = &fdnames;

    for (fn = fdnames; fn; fn = fn->next) {
	if (fn->fd == fd) {
	    *prevnext = fn->next;
	    free(fn->name);
	    free(fn);
	    break;
	}
	prevnext = &fn->next;
    }
}

/* 
 * The following UTF-8 validation is borrowed from
 * ftp://ftp.unicode.org/Public/PROGRAMS/CVTUTF/ConvertUTF.c.
 */

/*
 * Copyright 2001-2004 Unicode, Inc.
 * 
 * Disclaimer
 * 
 * This source code is provided as is by Unicode, Inc. No claims are
 * made as to fitness for any particular purpose. No warranties of any
 * kind are expressed or implied. The recipient agrees to determine
 * applicability of information provided. If this file has been
 * purchased on magnetic or optical media from Unicode, Inc., the
 * sole remedy for any claim will be exchange of defective media
 * within 90 days of receipt.
 * 
 * Limitations on Rights to Redistribute This Code
 * 
 * Unicode, Inc. hereby grants the right to freely use the information
 * supplied in this file in the creation of products supporting the
 * Unicode Standard, and to make copies of this file in any form
 * for internal or external distribution as long as this notice
 * remains attached.
 */

/*
 * Index into the table below with the first byte of a UTF-8 sequence to
 * get the number of trailing bytes that are supposed to follow it.
 * Note that *legal* UTF-8 values can't have 4 or 5-bytes. The table is
 * left as-is for anyone who may want to do such conversion, which was
 * allowed in earlier algorithms.
 */
static const char trailingBytesForUTF8[256] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5
};

/*
 * Utility routine to tell whether a sequence of bytes is legal UTF-8.
 * This must be called with the length pre-determined by the first byte.
 * If not calling this from ConvertUTF8to*, then the length can be set by:
 *  length = trailingBytesForUTF8[*source]+1;
 * and the sequence is illegal right away if there aren't that many bytes
 * available.
 * If presented with a length > 4, this returns 0.  The Unicode
 * definition of UTF-8 goes up to 4-byte sequences.
 */

static int isLegalUTF8(const unsigned char *source, int length)
{
    unsigned char a;
    const unsigned char *srcptr = source + length;

#if 0
    switch (length) {
	default:
	    return 0;
	    /* Everything else falls through when "1"... */

    if (length == 4) {
	if ((a = (*--srcptr)) < 0x80 || a > 0xBF) {
	    return 0;
	}
    }

    if (length >= 3) {
	if ((a = (*--srcptr)) < 0x80 || a > 0xBF) {
	    return 0;
	}
    }

    if (length >= 2) {
	if ((a = (*--srcptr)) > 0xBF) {
	    return 0;
	}

	switch (*source) {
	    /* no fall-through in this inner switch */
	case 0xE0:
	    if (a < 0xA0) return 0;
	    break;
	case 0xED:
	    if (a > 0x9F) return 0;
	    break;
	case 0xF0:
	    if (a < 0x90) return 0;
	    break;
	case 0xF4:
	    if (a > 0x8F) return 0;
	    break;
	default:
	    if (a < 0x80) return 0;
	}
    }

    if (length >= 1)
	if (*source >= 0x80 && *source < 0xC2) {
		return 0;
	}
    }
#else
    switch (length) {
	default:
	    return 0;
	    /* Everything else falls through when "1"... */
	case 4:
	    if ((a = (*--srcptr)) < 0x80 || a > 0xBF)
		return 0;
	case 3:
	    if ((a = (*--srcptr)) < 0x80 || a > 0xBF)
		return 0;
	case 2:
	    if ((a = (*--srcptr)) > 0xBF)
		return 0;

	    switch (*source) {
		    /* no fall-through in this inner switch */
		case 0xE0:
		    if (a < 0xA0)
			return 0;
		    break;
		case 0xED:
		    if (a > 0x9F)
			return 0;
		    break;
		case 0xF0:
		    if (a < 0x90)
			return 0;
		    break;
		case 0xF4:
		    if (a > 0x8F)
			return 0;
		    break;
		default:
		    if (a < 0x80)
			return 0;
	    }

	case 1:
	    if (*source >= 0x80 && *source < 0xC2)
		return 0;
    }
#endif
    if (*source > 0xF4)
	return 0;
    return 1;
}

/* End of code borrowed from ConvertUTF.c */

int isLegalUTF8String(const unsigned char *source)
{
    const unsigned char *seq, *sourceend;
    int seqlen;

    sourceend = source + strlen((char *)source);
    seq = source;

    while (seq < sourceend) {
	seqlen = trailingBytesForUTF8[*seq] + 1;
	if (!isLegalUTF8(seq, seqlen))
	    return 0;
	seq += seqlen;
    }

    return 1;
}

/* Translate an internal representation of a path (like /c/home) to
   a Windows path (like c:\home) */
static wchar_t *intpath2winpath(const char *intpath)
{
    wchar_t *winpath;
    int winpath_len;
    wchar_t *slash;
    const char *lastrootslash;
    wchar_t *lastslash;
    size_t intlen;

    /* Verify that input is valid UTF-8. We cannot use MB_ERR_INVALID_CHARS
       to MultiByteToWideChar, since it's only available in late versions of
       Windows. */
    if (!isLegalUTF8String((unsigned char *)intpath)) {
	logmsg(LOG_CRIT, "intpath2winpath: Illegal UTF-8 string:%s", intpath);
	return NULL;
    }

    /* Skip over multiple root slashes for paths like ///home/john */
    lastrootslash = intpath;
    while (*lastrootslash == '/')
	lastrootslash++;
    if (lastrootslash != intpath)
	lastrootslash--;

    intlen = strlen(lastrootslash);
    /* One extra for /c -> c:\ */
    winpath_len = sizeof(wchar_t) * (intlen + 2);
    winpath = malloc(winpath_len);
    if (!winpath) {
	logmsg(LOG_CRIT, "intpath2winpath: Unable to allocate memory");
	return NULL;
    }

    if (!MultiByteToWideChar
	(CP_UTF8, 0, lastrootslash, -1, winpath, winpath_len)) {
	logmsg(LOG_CRIT, "intpath2winpath: MultiByteToWideChar failed");
	return NULL;
    }

    /* If path ends with /.., chop of the last component. Eventually, we
       might want to eliminate all occurances of .. */
    lastslash = wcsrchr(winpath, '/');
    if (lastslash && !wcscmp(lastslash, L"/..")) {
	*lastslash = '\0';
	lastslash = wcsrchr(winpath, '/');
	*lastslash = '\0';
    }

    /* Translate /x -> x:/ and /x/something -> x:/something */
    if ((winpath[0] == '/') && winpath[1]) {
	switch (winpath[2]) {
	    case '\0':
		winpath[2] = '/';
		winpath[3] = '\0';
		/* fall through */

	    case '/':
		winpath[0] = winpath[1];
		winpath[1] = ':';
		break;

	    default:
		break;
	}
    }

    while ((slash = wcschr(winpath, '/')) != NULL) {
	*slash = '\\';
    }

    return winpath;
}

int win_seteuid(uid_t euid)
{
    fake_euid = euid;
    return 0;
}

int win_setegid(gid_t egid)
{
    fake_egid = egid;
    return 0;
}

int win_truncate(const char *path, off_t length)
{
    int fd, ret, saved_errno;

    fd = win_open(path, O_WRONLY);
    if (fd < 0)
	return -1;
    ret = chsize(fd, length);
    saved_errno = errno;
    win_close(fd);
    errno = saved_errno;

    return ret;
}

static int priv_chown(wchar_t *path, int nodereference, uid_t owner, gid_t group)
{
    int ret = -1;

    if (WSL_SetParameters(path, nodereference, -1, owner, group, -1)) {
	ret = 0;
    } else {
	errno = EINVAL;
    }

    return ret;
}

int win_chown(const char *path, uid_t owner, gid_t group)
{
    wchar_t *winpath;
    int ret = -1;

    winpath = intpath2winpath(path);
    if (!winpath) {
	errno = EINVAL;
	return -1;
    }

    ret = priv_chown(winpath, 0, owner, group);

    free(winpath);
    return ret;
}

int win_fchown(int fd, uid_t owner, gid_t group)
{
    return win_chown(get_fdname(fd), owner, group);
}

int win_lchown(const char *path, uid_t owner, gid_t group)
{
    wchar_t *winpath;
    int ret = -1;

    winpath = intpath2winpath(path);
    if (!winpath) {
	errno = EINVAL;
	return -1;
    }

    ret = priv_chown(winpath, 1, owner, group);

    free(winpath);
    return ret;
}

int win_fchmod(int fildes, mode_t mode)
{
    return win_chmod(get_fdname(fildes), mode);
}

int inet_aton(const char *cp, struct in_addr *addr)
{
    addr->s_addr = inet_addr(cp);
    return (addr->s_addr == INADDR_NONE) ? 0 : 1;
}

/* 
   If you need a good laugh, take a look at the "Suggested Interix
   replacement" at:
   http://msdn.microsoft.com/library/default.asp?url=/library/en-us/dnucmg/html/UCMGch10.asp
*/
ssize_t pread(int fd, void *buf, size_t count, off64_t offset)
{
    ssize_t size;
    __int64 ret;

    if ((ret = _lseeki64(fd, (__int64)offset, SEEK_SET)) < 0) {
	fprintf(stderr, "Seeking for offset %I64d failed when reading.\n", offset);
	return -1;
    }

    size = read(fd, buf, count);
    return size;
}

ssize_t pwrite(int fd, const void *buf, size_t count, off64_t offset)
{
    ssize_t size;
    __int64 ret;

    if ((ret = _lseeki64(fd, (__int64)offset, SEEK_SET)) < 0) {
	fprintf(stderr, "Seeking for offset %I64d failed when writing.\n", offset);
	return -1;
    }

    size = write(fd, buf, count);
    return size;
}

void syslog(U(int priority), U(const char *format), ...)
{
    assert(0);
}

int win_init()
{
    WORD winsock_ver;
    WSADATA wsadata;

    /* Set up locale, so that string compares works correctly */
    setlocale(LC_ALL, "");

#if 0
    /* Verify that -s is used */
    if (!opt_singleuser) {
	fprintf(stderr, "Single-user mode is required on this platform.\n");
	exit(1);
    }
#endif

    /* Verify that -d is used */
    if (opt_detach) {
	fprintf(stderr,
		"Foreground (debug) mode is required on this platform.\n");
	exit(1);
    }

    /* init winsock */
    winsock_ver = MAKEWORD(1, 1);
    if (WSAStartup(winsock_ver, &wsadata)) {
	fprintf(stderr, "Unable to initialise WinSock\n");
	exit(1);
    }
    if (LOBYTE(wsadata.wVersion) != 1 || HIBYTE(wsadata.wVersion) != 1) {
	fprintf(stderr, "WinSock version is incompatible with 1.1\n");
	WSACleanup();
	exit(1);
    }

    /* disable error popups, for example from drives not ready */
    SetErrorMode(SEM_FAILCRITICALERRORS);

    return 0;
}

void win_shutdown()
{
    WSACleanup();
}

/* Wrapper for Windows stat/lstat function, which provides
   st_dev and st_ino. These are calculated as follows:

   st_dev is set to the drive number (0=A 1=B ...). Our virtual root
   "/" gets a st_dev of 0xff. 

   st_ino is hashed from the full file path. Each half produces a 32
   bit hash. These are concatenated to a 64 bit value. The risk that
   st_ino is the same for two files on the system is, if I'm not
   mistaken, b=pigeon(2**32, f)**2. For f=1000, b=1e-08. By using a 64
   bit hash function this risk can be lowered. Possible future
   enhancement.

   pigeon() can be calculated in Python with:

   def pigeon(m, n):
       res = 1.0
       for i in range(m - n + 1, m):
           res = res * i / m
       return 1 - res

   l_mode = 0 for stat, 1 for lstat
*/
static int priv_stat(const char *file_name, backend_statstruct *buf, int l_mode)
{
    wchar_t *winpath;
    int ret;
    wchar_t pathbuf[4096];
    int retval;
    size_t namelen;
    wchar_t *splitpoint;
    char savedchar;
    unsigned long long fti;
    mode_t wsl_mode = 0;
    int wsl_extinfo;
    uid_t wsl_owner, wsl_group;
    dev_t wsl_dev;
    LXSS_FILE_EXTENDED_ATTRIBUTES_V1 lxattr;
    BOOL uselxattr;

    /* Special case: Our top-level virtual root, containing each drive
       represented as a directory. Compare with "My Computer" etc. This
       virtual root has a hardcoded hash value of 1, to simplify debugging
       etc. */
    if (!strcmp(file_name, "/")) {
	buf->st_mode = S_IFDIR | S_IRUSR | S_IWUSR;
	buf->st_nlink = MAX_NUM_DRIVES + 3;	/* 3 extra for: . .. / */
	buf->st_uid = 1;
	buf->st_gid = 1;
	buf->st_rdev = 0;
	buf->st_size = 4096;
	buf->st_atime = 0;
	buf->st_mtime = 0;
	buf->st_ctime = 0;
	buf->st_dev = 0xff;
	buf->st_ino = 1;
	return 0;
    }

    /* Since we're using FindFile() we have to make sure no one is
       trying to sneak in wildcard characters */
    if (strcspn(file_name, "*?<>\"") != strlen(file_name)) {
	errno = EINVAL;
	return -1;
    }

    winpath = intpath2winpath(file_name);
    if (!winpath) {
	errno = EINVAL;
	return -1;
    }



	struct _stati64 win_statbuf;
	ret = _wstati64(winpath, &win_statbuf);
	if (ret < 0) {
	    free(winpath);
	    return ret;
	}





    int ext_info;
    wchar_t target[PATH_MAX];
    int target_size = WSL_ReadLinkW(winpath, target, sizeof(target), &ext_info);

    int noderef = (target_size == -1 && ext_info > WSL_LINK) ? 1 : 0;

    if (!WSL_GetParameters(winpath, noderef | l_mode, &wsl_mode, &wsl_owner, &wsl_group, &wsl_dev, NULL, NULL)) {
	// fallback

	wsl_mode = (win_statbuf.st_mode & ~(S_IRWXG | S_IRWXO)) |
		   ((win_statbuf.st_mode & S_IFDIR)?(S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH):(S_IXUSR | S_IRGRP | S_IROTH));

	switch (ext_info) {
	case WSL_LINK:
	    wsl_mode = S_IFLNK | (S_IRWXU | S_IRWXG | S_IRWXO);
	    break;
	case WSL_FIFO:
	    wsl_mode = S_IFIFO | (wsl_mode & ~S_IFMT);
	    break;
	case WSL_CHR:
	    wsl_mode = S_IFCHR | (wsl_mode & ~S_IFMT);
	    break;
	case WSL_BLK:
	    wsl_mode = S_IFBLK | (wsl_mode & ~S_IFMT);
	    break;
	}

//	wsl_owner = win_statbuf.st_uid;
//	wsl_group = win_statbuf.st_gid;
//	wsl_dev = win_statbuf.st_rdev;
    }

    buf->st_mode = wsl_mode;

    if ((int) wsl_owner != -1) {
	buf->st_uid = wsl_owner;
    } else {
	buf->st_uid = 0;
    }

    if ((int) wsl_group != -1) {
	buf->st_gid = wsl_group;
    } else {
	buf->st_gid = 0;
    }

    if (wsl_dev != (dev_t)-1) {
	buf->st_rdev = wsl_dev;
    } else {
	buf->st_rdev = 0;
    }


{
    BY_HANDLE_FILE_INFORMATION fileinfo;

//    HANDLE hFile = GetFileHandle(winpath, FALSE, NULL, NULL);
    HANDLE hFile = CreateFileW(winpath,
			       0,
			       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			       NULL,
			       OPEN_EXISTING,
			       FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
			       NULL);

    if (hFile != INVALID_HANDLE_VALUE) {
	if (GetFileInformationByHandle(hFile, &fileinfo)) {
	    //wprintf(L"%s: %08X%08X\n", winpath, fileinfo.nFileIndexHigh, fileinfo.nFileIndexLow);
	    buf->st_ino = (uint64)((uint64)fileinfo.nFileIndexHigh << 32) | fileinfo.nFileIndexLow;

	    fti = (unsigned long long)fileinfo.ftLastAccessTime.dwHighDateTime << 32 | fileinfo.ftLastAccessTime.dwLowDateTime;
	    buf->st_atime = fti / 10000000 - FT70SEC;
	    fti = (unsigned long long)fileinfo.ftLastWriteTime.dwHighDateTime << 32 | fileinfo.ftLastWriteTime.dwLowDateTime;
	    buf->st_mtime = fti / 10000000 - FT70SEC;
	    /* Windows doesn't have "change time", so use modification time */
	    buf->st_ctime = buf->st_mtime;

	    buf->st_nlink = fileinfo.nNumberOfLinks; //win_statbuf.st_nlink;

	if (l_mode && target_size != -1) {
	    buf->st_size = WideCharToMultiByte(CP_UTF8, 0, target, target_size / sizeof(wchar_t), NULL, 0, NULL, NULL);
	} else {
	    buf->st_size = fileinfo.nFileSizeLow;
	}

	buf->st_blocks = buf->st_size / 512;

	} else {
	    //logmsg(LOG_ERR, "%s: GetFileInformationByHandle()", __func__);
	    //wprintf(L">>>%s\n", winpath);
	    errno = ENOENT;
	    free(winpath);
	    CloseHandle(hFile);
	    return -1;
	}

	CloseHandle(hFile);
    } else {
	//logmsg(LOG_ERR, "%s: Cannot open file %s", __func__, file_name);
	//wprintf(L">>>%s\n", winpath);
	errno = ENOENT;
	free(winpath);
	return -1;
    }
}

    buf->st_dev = tolower('C') - 'a';

#if 0
    fprintf(stderr,
	    "win_stat: file=%s, ret=%d, st_dev=0x%x, st_ino=0x%I64x\n",
	    file_name, ret, buf->st_dev, buf->st_ino);
#endif
    free(winpath);
    return ret;
}

int win_stat(const char *file_name, backend_statstruct * buf)
{
    return priv_stat(file_name, buf, 0);
}

int win_lstat(const char *file_name, backend_statstruct * buf)
{
    return priv_stat(file_name, buf, 1);
}

int win_open(const char *pathname, int flags, ...)
{
    va_list args;
    mode_t mode;
    int fd;
    wchar_t *winpath;

    va_start(args, flags);
    mode = va_arg(args, int);

    va_end(args);

    winpath = intpath2winpath(pathname);
    if (!winpath) {
	errno = EINVAL;
	return -1;
    }

    fd = _wopen(winpath, flags | O_BINARY, mode);

    if (fd != -1 && flags & O_CREAT) {
	if (!WSL_SetParameters(winpath, 0, mode | S_IFREG, fake_euid, fake_egid, -1)) {
	    logmsg(LOG_ERR, "%s: Can't set WSL mode!", __func__);
	}
    }

    free(winpath);
    if (fd < 0) {
	return fd;
    }

    return add_fdname(fd, pathname);
}

int win_close(int fd)
{
    remove_fdname(fd);
    return close(fd);
}

int win_fstat(int fd, backend_statstruct * buf)
{
    return win_stat(get_fdname(fd), buf);
}

/*
  opendir implementation which emulates a virtual root with the drive
  letters presented as directories. 
*/
UNFS3_WIN_DIR *win_opendir(const char *name)
{
    wchar_t *winpath;
    UNFS3_WIN_DIR *ret;

    ret = malloc(sizeof(UNFS3_WIN_DIR));
    if (!ret) {
	logmsg(LOG_CRIT, "win_opendir: Unable to allocate memory");
	return NULL;
    }

    if (!strcmp("/", name)) {
	/* Emulate root */
	ret->stream = NULL;
	ret->currentdrive = 0;
	ret->logdrives = GetLogicalDrives();
    } else {
	winpath = intpath2winpath(name);
	if (!winpath) {
	    free(ret);
	    errno = EINVAL;
	    return NULL;
	}

	ret->stream = _wopendir(winpath);
	free(winpath);
	if (ret->stream == NULL) {
	    free(ret);
	    ret = NULL;
	}
    }

    return ret;
}

struct dirent *win_readdir(UNFS3_WIN_DIR * dir)
{
    if (dir->stream == NULL) {
	/* Emulate root */
	for (; dir->currentdrive < MAX_NUM_DRIVES; dir->currentdrive++) {
	    if (dir->logdrives & 1 << dir->currentdrive)
		break;
	}

	if (dir->currentdrive < MAX_NUM_DRIVES) {
	    dir->de.d_name[0] = 'a' + dir->currentdrive;
	    dir->de.d_name[1] = '\0';
	    dir->currentdrive++;
	    return &dir->de;
	} else {
	    return NULL;
	}
    } else {
	struct _wdirent *de;

	de = _wreaddir(dir->stream);
	if (!de) {
	    return NULL;
	}

	if (!WideCharToMultiByte
	    (CP_UTF8, 0, de->d_name, -1, dir->de.d_name,
	     sizeof(dir->de.d_name), NULL, NULL)) {
	    logmsg(LOG_CRIT, "win_readdir: WideCharToMultiByte failed");
	    return NULL;
	}
	return &dir->de;
    }
}

int win_closedir(UNFS3_WIN_DIR * dir)
{
    if (dir->stream == NULL) {
	free(dir);
	return 0;
    } else {
	return _wclosedir(dir->stream);
    }
}

void openlog(U(const char *ident), U(int option), U(int facility))
{

}

char *win_realpath(const char *path, char *resolved_path)
{
    return normpath(path, resolved_path);
}

int win_readlink(const char *path, char *buf, size_t bufsiz)
{
    wchar_t target[PATH_MAX];
    int target_size = -1;

    wchar_t *winpath = intpath2winpath(path);
    if (!winpath) {
	errno = EINVAL;
	return -1;
    }

    target_size = WSL_ReadLinkW(winpath, target, sizeof(target), NULL);

    if (target_size > 0) {
	for (unsigned int i = 0; i < (target_size / sizeof(wchar_t)); i++) {
	    if (target[i] == '\\') {
		target[i] = '/';
	    }
	}
	// get size in utf-8
	target_size = WideCharToMultiByte(CP_UTF8, 0, target, target_size / sizeof(wchar_t), buf, bufsiz, NULL, NULL);
    }

    if (target_size == 0) {
	target_size = -1;
    }

    free(winpath);

    return target_size;
}

int win_mkdir(const char *pathname, mode_t mode)
{
    wchar_t *winpath;
    int ret;

    if (!strcmp("/", pathname)) {
	/* Emulate root */
	errno = EROFS;
	return -1;
    }

    winpath = intpath2winpath(pathname);
    if (!winpath) {
	errno = EINVAL;
	return -1;
    }

    /* FIXME: Use mode */
    ret = _wmkdir(winpath);

    if (ret != -1) {
	if (!WSL_SetParameters(winpath, 0, mode | S_IFDIR, fake_euid, fake_egid, -1)) {
	    logmsg(LOG_ERR, "%s: Can't set WSL mode!", __func__);
	}
    }

    free(winpath);

    return ret;
}

int win_symlink(const char *oldpath, const char *newpath)
{
    int ret = -1;

    wchar_t *winoldpath = intpath2winpath(oldpath);
    if (!winoldpath) {
	errno = EINVAL;
	return -1;
    }

    wchar_t *winnewpath = intpath2winpath(newpath);
    if (!winnewpath) {
	free(winoldpath);
	errno = EINVAL;
	return -1;
    }

    wchar_t *wexport_path = intpath2winpath(export_path);
    if (!winnewpath) {
	free(winnewpath);
	free(winoldpath);
	errno = EINVAL;
	return -1;
    }

    wchar_t tmppath[wcslen(winoldpath) + wcslen(winnewpath) + 4];

    if (winoldpath[0] == '\\') {
	wcscpy(tmppath, winoldpath);
    } else {
	wcscpy(tmppath, winnewpath);
	wchar_t *lastslash = wcsrchr(tmppath, '\\');
	if (lastslash) {
	    wcscpy(&lastslash[1], winoldpath);
	}
    }

    wchar_t can_tmppath[sizeof(tmppath)];

    if (!PathCanonicalizeW(can_tmppath, tmppath)) {
	wcscpy(can_tmppath, tmppath);
    }

    DWORD attr;

    if (wcsncmp(can_tmppath, wexport_path, wcslen(wexport_path)) ||
	(attr = GetFileAttributesW(tmppath)) == INVALID_FILE_ATTRIBUTES) {
	ret = WSL_SymLinkW(winoldpath, winnewpath, SYMLINK_JUNCPOINT, oldpath);
    } else {
	ret = WSL_SymLinkW(winoldpath, winnewpath, (attr & FILE_ATTRIBUTE_DIRECTORY)?SYMLINK_DIRECTORY:0, oldpath);
    }

    if (ret != -1) {
	if (!WSL_SetParameters(winnewpath, 1, S_IFLNK | S_IRWXU | S_IRWXG | S_IRWXO, fake_euid, fake_egid, -1)) {
	    logmsg(LOG_ERR, "%s: Cannot set WSL mode", __func__);
	}
    }

    free(wexport_path);
    free(winnewpath);
    free(winoldpath);

    return ret;
}

int win_mknod(const char *pathname, mode_t mode, dev_t dev)
{
    wchar_t *winpath;
    int wsl_type;
    int ret;

    if (!strcmp("/", pathname)) {
	/* Emulate root */
	errno = EROFS;
	return -1;
    }

    winpath = intpath2winpath(pathname);
    if (!winpath) {
	errno = EINVAL;
	return -1;
    }

    if (mode & S_IFIFO) wsl_type = WSL_FIFO;
    else if (mode & S_IFCHR) wsl_type = WSL_CHR;
    else if (mode & S_IFBLK) wsl_type = WSL_BLK;
    else wsl_type = 0;

    ret = WSL_MakeSpecialFile(winpath, wsl_type);

    if (ret != -1) {
	if (WSL_SetParameters(winpath, 1, mode, fake_euid, fake_egid, dev) == FALSE) {
	    logmsg(LOG_ERR, "%s: Can't set WSL mode!", __func__);
	}
    }

    free(winpath);

    return ret;
}

int win_mkfifo(const char *pathname, mode_t mode)
{
    wchar_t *winpath;
    int ret;

    if (!strcmp("/", pathname)) {
	/* Emulate root */
	errno = EROFS;
	return -1;
    }

    winpath = intpath2winpath(pathname);
    if (!winpath) {
	errno = EINVAL;
	return -1;
    }

    ret = WSL_MakeSpecialFile(winpath, WSL_FIFO);

    if (WSL_SetParameters(winpath, 1, S_IFIFO | mode, fake_euid, fake_egid, -1) == FALSE) {
	logmsg(LOG_ERR, "%s: Can't set WSL mode!", __func__);
    }

    free(winpath);

    return ret;
}

int win_link(const char *oldpath, const char *newpath)
{
    int ret = -1;

    wchar_t *winoldpath = intpath2winpath(oldpath);
    if (!winoldpath) {
	errno = EINVAL;
	return -1;
    }

    wchar_t *winnewpath = intpath2winpath(newpath);
    if (!winnewpath) {
	free(winoldpath);
	errno = EINVAL;
	return -1;
    }

    wchar_t *wexport_path = intpath2winpath(export_path);
    if (!winnewpath) {
	free(winnewpath);
	free(winoldpath);
	errno = EINVAL;
	return -1;
    }

    wchar_t tmppath[wcslen(winoldpath) + wcslen(winnewpath) + 4];

    if (winoldpath[0] == '\\') {
	wcscpy(tmppath, winoldpath);
    } else {
	wcscpy(tmppath, winnewpath);
	wchar_t *lastslash = wcsrchr(tmppath, '\\');
	if (lastslash) {
	    wcscpy(&lastslash[1], winoldpath);
	}
    }

    wchar_t can_tmppath[sizeof(tmppath)];

    if (!PathCanonicalizeW(can_tmppath, tmppath)) {
	wcscpy(can_tmppath, tmppath);
    }

    if (wcsncmp(can_tmppath, wexport_path, wcslen(wexport_path))) {
	errno = EACCES;
    } else {
	if (CreateHardLinkW(winnewpath, winoldpath, NULL)) {
	    ret = 0;
	} else {
	    errno = EIO;
	}
    }

    free(wexport_path);
    free(winnewpath);
    free(winoldpath);

    return ret;
}

int win_statvfs(const char *path, backend_statvfsstruct * buf)
{
    wchar_t *winpath;
    DWORD SectorsPerCluster;
    DWORD BytesPerSector;
    DWORD NumberOfFreeClusters;
    DWORD TotalNumberOfClusters;
    ULARGE_INTEGER FreeBytesAvailable;
    ULARGE_INTEGER TotalNumberOfBytes;
    ULARGE_INTEGER TotalNumberOfFreeBytes;

    if (!strcmp("/", path)) {
	/* Emulate root */
	buf->f_frsize = 1024;
	buf->f_blocks = 1024;
	buf->f_bfree = 0;
	buf->f_bavail = 0;
	buf->f_files = 1024;
	buf->f_ffree = 0;
	return 0;
    }

    winpath = intpath2winpath(path);
    if (!winpath) {
	errno = EINVAL;
	return -1;
    }

    winpath[3] = '\0';		       /* Cut off after x:\ */

    if (!GetDiskFreeSpaceW
	(winpath, &SectorsPerCluster, &BytesPerSector, &NumberOfFreeClusters,
	 &TotalNumberOfClusters)) {
	errno = EIO;
	return -1;
    }

    if (!GetDiskFreeSpaceExW
	(winpath, &FreeBytesAvailable, &TotalNumberOfBytes,
	 &TotalNumberOfFreeBytes)) {
	errno = EIO;
	return -1;
    }

    buf->f_frsize = BytesPerSector;
    buf->f_blocks = TotalNumberOfBytes.QuadPart / BytesPerSector;
    buf->f_bfree = TotalNumberOfFreeBytes.QuadPart / BytesPerSector;
    buf->f_bavail = FreeBytesAvailable.QuadPart / BytesPerSector;
    buf->f_files = buf->f_blocks / SectorsPerCluster;
    buf->f_ffree = buf->f_bfree / SectorsPerCluster;
    free(winpath);
    return 0;
}

int win_remove(const char *pathname)
{
    wchar_t *winpath;
    int ret;

    if (!strcmp("/", pathname)) {
	/* Emulate root */
	errno = EROFS;
	return -1;
    }

    winpath = intpath2winpath(pathname);
    if (!winpath) {
	errno = EINVAL;
	return -1;
    }

    DWORD attr = GetFileAttributesW(winpath);
    if (attr == INVALID_FILE_ATTRIBUTES) {
	errno = EACCES;
	ret = -1;
    } else if (attr & FILE_ATTRIBUTE_REPARSE_POINT) {
	BOOL bret;
	if (attr & FILE_ATTRIBUTE_DIRECTORY) {
	    bret = RemoveDirectoryW(winpath);
	} else {
	    bret = DeleteFileW(winpath);
	}
	if (bret == FALSE) {
	    errno = EIO;
	    ret = -1;
	}
    } else {
	ret = _wremove(winpath);
    }

    free(winpath);

    return ret;
}

int win_chmod(const char *path, mode_t mode)
{
    wchar_t *winpath;
    int ret;
    mode_t wsl_mode;

    if (!strcmp("/", path)) {
	/* Emulate root */
	errno = EROFS;
	return -1;
    }

    winpath = intpath2winpath(path);
    if (!winpath) {
	errno = EINVAL;
	return -1;
    }

    DWORD attr = GetFileAttributesW(winpath);
    if (attr == INVALID_FILE_ATTRIBUTES) {
	errno = EACCES;
	free(winpath);
	return -1;
    }

    int ext_info;
    int noderef = (WSL_ReadLinkW(winpath, NULL, 0, &ext_info) == -1 && ext_info > WSL_LINK) ? 1 : 0;

    if (!WSL_GetParameters(winpath, noderef, &wsl_mode, NULL, NULL, NULL, NULL, NULL)) {
	switch (ext_info) {
	case WSL_FIFO:
	    wsl_mode = S_IFIFO |
		       ((attr & FILE_ATTRIBUTE_READONLY)?0:S_IWUSR) |
		       S_IRUSR | S_IXUSR | S_IRGRP | S_IROTH;
	    break;
	case WSL_CHR:
	    wsl_mode = S_IFCHR |
		       ((attr & FILE_ATTRIBUTE_READONLY)?0:S_IWUSR) |
		       S_IRUSR | S_IXUSR | S_IRGRP | S_IROTH;
	    break;
	case WSL_BLK:
	    wsl_mode = S_IFBLK |
		       ((attr & FILE_ATTRIBUTE_READONLY)?0:S_IWUSR) |
		       S_IRUSR | S_IXUSR | S_IRGRP | S_IROTH;
	    break;
	default:
	    wsl_mode = ((attr & FILE_ATTRIBUTE_DIRECTORY)?S_IFDIR|S_IXGRP|S_IXOTH:S_IFREG) |
		       ((attr & FILE_ATTRIBUTE_READONLY)?0:S_IWUSR) |
		       S_IRUSR | S_IXUSR | S_IRGRP | S_IROTH;
	    break;
	}
    }

    if (!WSL_SetParameters(winpath, noderef, (wsl_mode & S_IFMT) | mode, -1, -1, -1)) {
	logmsg(LOG_ERR, "%s: Can't set WSL mode!", __func__);
	errno = EACCES;
    } else {
	ret = 0;
    }

    if (!noderef) {
	ret = _wchmod(winpath, mode);
    }

    free(winpath);
    return ret;
}

int win_utime(const char *path, const struct utimbuf *times)
{
    wchar_t *winpath;
    int ret = 0;
    HANDLE h;
    unsigned long long fti;
    FILETIME atime, mtime;

    if (!strcmp("/", path)) {
	/* Emulate root */
	errno = EROFS;
	return -1;
    }

    winpath = intpath2winpath(path);
    if (!winpath) {
	errno = EINVAL;
	return -1;
    }

    /* Unfortunately, we cannot use utime(), since it doesn't support
       directories. */
    fti = ((unsigned long long)times->actime + FT70SEC) * 10000000;
    atime.dwHighDateTime = (fti >> 32) & 0xffffffff;
    atime.dwLowDateTime = fti & 0xffffffff;
    fti = ((unsigned long long)times->modtime + FT70SEC) * 10000000;
    mtime.dwHighDateTime = (fti >> 32) & 0xffffffff;
    mtime.dwLowDateTime = fti & 0xffffffff;

    h = CreateFileW(winpath, FILE_WRITE_ATTRIBUTES,
		    FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
		    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS, NULL);

    if (!SetFileTime(h, NULL, &atime, &mtime)) {
	errno = EACCES;
	ret = -1;
    }

    CloseHandle(h);
    free(winpath);
    return ret;
}

int win_rmdir(const char *path)
{
    wchar_t *winpath;
    int ret;

    if (!strcmp("/", path)) {
	/* Emulate root */
	errno = EROFS;
	return -1;
    }

    winpath = intpath2winpath(path);
    if (!winpath) {
	errno = EINVAL;
	return -1;
    }

    ret = _wrmdir(winpath);
    free(winpath);
    return ret;
}

int win_rename(const char *oldpath, const char *newpath)
{
    wchar_t *oldwinpath, *newwinpath;
    int ret = 0;

    if (!strcmp("/", oldpath) && !strcmp("/", newpath)) {
	/* Emulate root */
	errno = EROFS;
	return -1;
    }

    oldwinpath = intpath2winpath(oldpath);
    if (!oldwinpath) {
	errno = EINVAL;
	return -1;
    }
    newwinpath = intpath2winpath(newpath);
    if (!newwinpath) {
	free(oldwinpath);
	errno = EINVAL;
	return -1;
    }

    DWORD attr = GetFileAttributesW(newwinpath);
    if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
	if (!DeleteFileW(newwinpath)) {
	    errno = EACCES;
	    goto out;
	}
    }

    if (!MoveFileW(oldwinpath, newwinpath)) {
	logmsg(LOG_ERR, "%s: error %ld", __func__, GetLastError());
	errno = EINVAL;
	ret = -1;
    }

//    ret = _wrename(oldwinpath, newwinpath);
out:
    free(oldwinpath);
    free(newwinpath);
    return ret;
}

int win_gen_nonce(char *nonce)
{
    HCRYPTPROV hCryptProv;

    if (!CryptAcquireContext
	(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
	logmsg(LOG_ERR, "CryptAcquireContext failed with error 0x%lx",
	       GetLastError());
	return -1;
    }

    if (!CryptGenRandom(hCryptProv, 32, (unsigned char *)nonce)) {
	logmsg(LOG_ERR, "CryptGenRandom failed with error 0x%lx",
	       GetLastError());
	return -1;
    }

    if (!CryptReleaseContext(hCryptProv, 0)) {
	logmsg(LOG_ERR, "CryptReleaseContext failed with error 0x%lx",
	       GetLastError());
	return -1;
    }

    return 0;
}

/* Just like strncasecmp, but compare two UTF8 strings. Limited to 4096 chars. */
int win_utf8ncasecmp(const char *s1, const char *s2, size_t n)
{
    wchar_t ws1[4096], ws2[4096];
    int converted;

    /* Make sure input is valid UTF-8 */
    if (!isLegalUTF8String((unsigned char *)s1)) {
	logmsg(LOG_CRIT, "win_utf8ncasecmp: Illegal UTF-8 string:%s", s1);
	return -1;
    }
    if (!isLegalUTF8String((unsigned char *)s2)) {
	logmsg(LOG_CRIT, "win_utf8ncasecmp: Illegal UTF-8 string:%s", s2);
	return -1;
    }

    /* Convert both strings to wide chars */
    converted = MultiByteToWideChar(CP_UTF8, 0, s1, n, ws1, wsizeof(ws1));
    if (!converted) {
	logmsg(LOG_CRIT, "win_utf8ncasecmp: MultiByteToWideChar failed");
	return -1;
    }
    ws1[converted] = '\0';
    converted = MultiByteToWideChar(CP_UTF8, 0, s2, n, ws2, wsizeof(ws2));
    if (!converted) {
	logmsg(LOG_CRIT, "win_utf8ncasecmp: MultiByteToWideChar failed");
	return 1;
    }
    ws2[converted] = '\0';

    /* compare */
    return _wcsicmp(ws1, ws2);
}

int win_access(const char *path, int mode)
{
    int ret = -1;
    mode_t f_mode;
    wchar_t *winpath;

    winpath = intpath2winpath(path);
    if (!winpath) {
	errno = EINVAL;
	return -1;
    }

    DWORD attr = GetFileAttributesW(winpath);
    if (attr == INVALID_FILE_ATTRIBUTES) {
	free(winpath);
	errno = EACCES;
	return -1;
    }

    if (!WSL_GetParameters(winpath, 0, &f_mode, NULL, NULL, NULL, NULL, NULL)) {
	f_mode = (attr & FILE_ATTRIBUTE_DIRECTORY)?
		(S_IRUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH):
		(S_IRUSR | S_IXUSR | S_IRGRP | S_IROTH);
	f_mode |= (attr & FILE_ATTRIBUTE_READONLY)?0:S_IWUSR;
    }

    if (mode == F_OK) {
	ret = 0;
    } else {
	ret  = (mode & X_OK) && (!(f_mode & (S_IXUSR | S_IXGRP)));
	ret |= (mode & R_OK) && (!(f_mode & (S_IRUSR | S_IRGRP)));
	ret |= (mode & W_OK) && (!(f_mode & (S_IWUSR | S_IWGRP)));
	ret = ret?-1:0;
    };

    free(winpath);
    return ret;
}

int win_set_cs_dir(const char *path, int enable)
{
    wchar_t *winpath;
    int ret = -1;

    winpath = intpath2winpath(path);
    if (!winpath) {
	errno = EINVAL;
	return -1;
    }

    if (!WSL_SetCsDirectory(winpath, enable)) {
	errno = EINVAL;
	ret = -1;
    }

    free(winpath);
    return ret;

}

#endif				       /* WIN32 */

/* ISO C forbids an empty source file */
typedef short pier;
