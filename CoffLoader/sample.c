#include <stdio.h>

__declspec(dllimport) int __cdecl MSVCRT$printf(const char *format, ...);

int a;

void hello() {
    MSVCRT$printf("Hello, COFF World!\n");
    a = 42;
    MSVCRT$printf("a = %d\n", a);
}

void go() {
    hello();
}
