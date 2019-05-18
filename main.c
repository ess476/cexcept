#include <stdio.h>
#include "cexcept.h"

int fact(int x) {

    printf("fact(%d)\n", x);
    if (x < 0) {
        throw(x);
    }

    try {
        return x * fact(x - 1);
    } catch(errno) {
        printf("catch: %x\n", x);
        return 1;
    }
}

int test() {
    char* x = "Hello, World!";

    try {

        char* msg;
        try {

            printf("fact(5): %d\n", fact(5));

        } catch(errno, msg) {

            printf("catch 1: %d : %s\n", errno, msg);

            return 183;
        }

        throw(111);
    } catch(errno) {
        printf("catch 2: %d\n", errno);

        return 123;

    }

    return 4;
}

int main() {

    int x = test();
    printf("%d\n", x);
}