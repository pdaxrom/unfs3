#include <stdio.h>
#include <windows.h>
#include "ntfsea.h"

int main(int argc, char *argv[])
{
    const size_t WCHARBUF = 100;
    wchar_t  wszDest[WCHARBUF];
    MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, argv[1], -1, wszDest, WCHARBUF);

    struct EaList *eaList = GetEaList(wszDest);
    if (eaList) {
	printf("List %d\n", eaList->ListSize);
	for (int i = 0; i < eaList->ListSize; i++) {
	    printf("%s\n", eaList->List[i].Name);
	}
    } else {
	printf("No list :(\n");
    }
    return 0;
}
