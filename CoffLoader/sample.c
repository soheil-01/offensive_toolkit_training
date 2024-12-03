#include <stdio.h>

__declspec(dllimport) int __cdecl MSVCRT$printf(const char *format, ...);


void hello() {
    MSVCRT$printf("Hello, COFF World!\n");
}

void go() {
    hello();
}
