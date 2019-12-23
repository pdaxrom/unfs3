#ifndef __WINLINKS_H__
#define __WINLINKS_H__

#define SYMLINK_JUNCPOINT	0x1
#define SYMLINK_DIRECTORY	0x2

#define WSL_UNK			0x0
#define WSL_LINK		0x1
#define WSL_FIFO		0x2
#define WSL_CHAR		0x3
#define WSL_BLK			0x4

ssize_t ReadLinkW(const wchar_t * pathname, wchar_t * buf, size_t bufsiz, int *extinfo);

int SymLinkW(const wchar_t *target, const wchar_t *linkpath, uint32_t mode, const char *origtarget);

int WSL_MakeSpecialFile(const wchar_t *pathname, int type);

BOOL WSL_SetCsDirectory(const wchar_t *pathname, int enable);

#endif
