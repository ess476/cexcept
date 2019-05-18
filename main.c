#include <stdio.h>
#include "cexcept.h"

int fact(int x) {

    printf("fact(%d)\n", x);
    if (x < 0) {
        throw(-1);
    }

    try {
        return x * fact(x - 1);
    } catch(errno) {
        printf("caught exception: %d\n", errno);
        print_stack_trace();

        return 1;
    }
}


int main() {


    try {
        fact(5);

        throw(12);
    } catch(errno) {
        printf("caught exception: %d\n", errno);

        print_stack_trace();
        throw(errno);
    }
}