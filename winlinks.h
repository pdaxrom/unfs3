#ifndef __WINLINKS_H__
#define __WINLINKS_H__

ssize_t ReadLinkW(const wchar_t * pathname, wchar_t * buf, size_t bufsiz);

int SymLinkW(const wchar_t *target, const wchar_t *linkpath);

#endif
