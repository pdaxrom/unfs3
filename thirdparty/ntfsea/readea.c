#include <stdio.h>
#include <windows.h>
#include <inttypes.h>
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
	    uint32_t *val = (uint32_t *)eaList->List[i].Value;
	    printf("%s [%d] %d\n", eaList->List[i].Name, eaList->List[i].ValueLength, *val);
	}
    } else {
	printf("No list :(\n");
    }
    return 0;
}
