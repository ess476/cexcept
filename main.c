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

int fact2(int x) {

    printf("fact(%d)\n", x);
    if (x < 0) {
        printf("%d\n", x);
        throw(65);
    }
    fact2(x - 1);
}


int main() {


    try {
        fact2(2);
    } catch(errno) {
        printf("ayy: %d\n", errno);
        throw(errno);
    }
}