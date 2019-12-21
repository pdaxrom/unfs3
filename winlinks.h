#ifndef __WINLINKS_H__
#define __WINLINKS_H__

#define SYMLINK_JUNCPOINT	0x1
#define SYMLINK_DIRECTORY	0x2

ssize_t ReadLinkW(const wchar_t * pathname, wchar_t * buf, size_t bufsiz);

int SymLinkW(const wchar_t *target, const wchar_t *linkpath, uint32_t mode, const char *origtarget);

#endif
