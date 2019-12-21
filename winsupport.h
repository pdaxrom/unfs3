
/*
 * unfs3 Windows compatibility
 * Copyright 2006 Peter Åstrand <astrand@cendio.se> for Cendio AB
 * see file LICENSE for license details
 */

#ifdef WIN32
#ifndef UNFS3_WINSUPPORT_H
#define UNFS3_WINSUPPORT_H

#include <sys/stat.h>
#include <dirent.h>
#include <utime.h>
#include "nfs.h"

#define LOG_EMERG       0       /* system is unusable */
#define LOG_ALERT       1       /* action must be taken immediately */
#define LOG_CRIT        2       /* critical conditions */
#define LOG_ERR         3       /* error conditions */
#define LOG_WARNING     4       /* warning conditions */
#define LOG_NOTICE      5       /* normal but significant condition */
#define LOG_INFO        6       /* informational */
#define LOG_DEBUG       7       /* debug-level messages */
#define LOG_CONS        0
#define LOG_PID         0
#define LOG_DAEMON      0
#define closelog()      do { } while (0)

#define O_NONBLOCK      0

#include "winerrno.h"

#define S_IFSOCK 0140000
#define S_IFLNK  0120000
#define S_ISLNK(m)	(((m) & S_IFMT) == S_IFLNK)

#undef S_IFBLK
#define S_IFBLK  0060000
#define W_S_IFBLK	0x3000
#define	W_S_ISBLK(m)	(((m) & S_IFMT) == W_S_IFBLK)

#if 0
#define W_S_IFMT	0xF000
#define W_S_IFREG	0x8000
#define W_S_IFDIR	0x4000
#define W_S_IFBLK	0x3000
#define W_S_IFCHR	0x2000
#define W_S_IFIFO	0x1000
#define W_S_IREAD	0x0100
#define W_S_IWRITE	0x0080
#define W_S_IEXEC	0x0040

#define	W_S_ISDIR(m)	(((m) & W_S_IFMT) == W_S_IFDIR)
#define	W_S_ISFIFO(m)	(((m) & W_S_IFMT) == W_S_IFIFO)
#define	W_S_ISCHR(m)	(((m) & W_S_IFMT) == W_S_IFCHR)
#define	W_S_ISBLK(m)	(((m) & W_S_IFMT) == W_S_IFBLK)
#define	W_S_ISREG(m)	(((m) & W_S_IFMT) == W_S_IFREG)

#undef S_ISDIR
#undef S_ISFIFO
#undef S_ISCHR
#undef S_ISBLK
#undef S_ISREG

#undef _S_IFBLK

#undef S_IFMT
#undef _S_IFMT
#undef S_IFDIR 
#undef _S_IFDIR
#undef S_IFCHR
#undef _S_IFCHR
#undef S_IFREG
#undef _S_IFREG
#undef S_IREAD
#undef _S_IREAD
#undef S_IWRITE
#undef _S_IWRITE
#undef S_IEXEC
#undef _S_IEXEC
#undef S_IFIFO
#undef _S_IFIFO
#undef S_IFBLK
#undef _S_IFBLK

#undef _S_IRWXU
#undef _S_IXUSR
#undef _S_IWUSR

#undef S_IRWXU
#undef S_IXUSR
#undef S_IWUSR
#undef S_IRUSR
#undef _S_IRUSR

#undef S_IRGRP
#undef S_IWGRP
#undef S_IXGRP
#undef S_IRWXG

#undef S_IROTH
#undef S_IWOTH
#undef S_IXOTH
#undef S_IRWXO

/* from linux/stat.h */

#define S_IFMT  00170000
#define S_IFSOCK 0140000
#define S_IFLNK  0120000
#define S_IFREG  0100000
#define S_IFBLK  0060000
#define S_IFDIR  0040000
#define S_IFCHR  0020000
#define S_IFIFO  0010000
#define S_ISUID  0004000
#define S_ISGID  0002000
#define S_ISVTX  0001000

#define S_ISLNK(m)	(((m) & S_IFMT) == S_IFLNK)
#define S_ISREG(m)	(((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m)	(((m) & S_IFMT) == S_IFDIR)
#define S_ISCHR(m)	(((m) & S_IFMT) == S_IFCHR)
#define S_ISBLK(m)	(((m) & S_IFMT) == S_IFBLK)
#define S_ISFIFO(m)	(((m) & S_IFMT) == S_IFIFO)
#define S_ISSOCK(m)	(((m) & S_IFMT) == S_IFSOCK)

#define S_IRWXU 00700
#define S_IRUSR 00400
#define S_IWUSR 00200
#define S_IXUSR 00100

#define S_IRWXG 00070
#define S_IRGRP 00040
#define S_IWGRP 00020
#define S_IXGRP 00010

#define S_IRWXO 00007
#define S_IROTH 00004
#define S_IWOTH 00002
#define S_IXOTH 00001
#endif

#ifndef SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
#define SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE	0x2
#endif

typedef int socklen_t;
typedef uint32 uid_t;
typedef uint32 gid_t;

typedef struct _backend_statstruct
{
        uint32  st_dev;  
        uint64  st_ino;  
        _mode_t st_mode;
        short   st_nlink;
        uint32  st_uid;
        uint32  st_gid;
        _dev_t  st_rdev;
        __int64 st_size;
        short   st_blksize;
        _off_t  st_blocks;
        time_t  st_atime;
        time_t  st_mtime;
        time_t  st_ctime;
} backend_statstruct;

typedef struct _backend_passwdstruct
{
    uid_t   pw_uid;
    gid_t   pw_gid;
} backend_passwdstruct;

/* Only includes fields actually used by unfs3 */
typedef struct _backend_statvfsstruct
{
        unsigned long  f_frsize;    /* file system block size */
        uint64         f_blocks;   /* size of fs in f_frsize units */
        uint64         f_bfree;    /* # free blocks */
        uint64         f_bavail;   /* # free blocks for non-root */
        uint64         f_files;    /* # inodes */
        uint64         f_ffree;    /* # free inodes */
} backend_statvfsstruct;

typedef struct _UNFS3_WIN_DIR
{
    _WDIR *stream; /* Windows DIR stream. NULL means root emulation */
    uint32 currentdrive; /* Next drive to check/return */
    struct dirent de;
    DWORD logdrives;
} UNFS3_WIN_DIR;

int inet_aton(const char *cp, struct in_addr *addr);
ssize_t pread(int fd, void *buf, size_t count, off64_t offset);
ssize_t pwrite(int fd, const void *buf, size_t count, off64_t offset);
void syslog(int priority, const char *format, ...);

int win_seteuid(uid_t euid);
int win_setegid(gid_t egid);
int win_truncate(const char *path, off_t length);
int win_chown(const char *path, uid_t owner, gid_t group);
int win_fchown(int fd, uid_t owner, gid_t group);
int win_fchmod(int fildes, mode_t mode);
int win_stat(const char *file_name, backend_statstruct *buf);
int win_lstat(const char *file_name, backend_statstruct *buf);
int win_fstat(int fd, backend_statstruct *buf);
int win_open(const char *pathname, int flags, ...);
int win_close(int fd);
UNFS3_WIN_DIR *win_opendir(const char *name);
struct dirent *win_readdir(UNFS3_WIN_DIR *dir);
int win_closedir(UNFS3_WIN_DIR *dir);
int win_init();
void openlog(const char *ident, int option, int facility);
char *win_realpath(const char *path, char *resolved_path);
int win_readlink(const char *path, char *buf, size_t bufsiz);
int win_mkdir(const char *pathname, mode_t mode);
int win_symlink(const char *oldpath, const char *newpath);
int win_mknod(const char *pathname, mode_t mode, dev_t dev);
int win_mkfifo(const char *pathname, mode_t mode);
int win_link(const char *oldpath, const char *newpath);
int win_statvfs(const char *path, backend_statvfsstruct *buf);
int win_remove(const char *pathname);
int win_chmod(const char *path, mode_t mode);
int win_utime(const char *path, const struct utimbuf *times);
int win_rmdir(const char *path);
int win_rename(const char *oldpath, const char *newpath);
int win_gen_nonce(char *nonce);
int win_utf8ncasecmp(const char *s1, const char *s2, size_t n);
int win_access(const char *pathname, int mode);

#endif /* UNFS3_WINSUPPORT_H */
#endif /* WIN32 */
