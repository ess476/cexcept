#include <stdio.h>
#include "cexcept.h"

#if 1
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
        fact(10);

        throw(12);
    } catch(errno) {
        printf("caught exception: %d from: %s:%d\n", errno, exception_ctx->src_ctx.file, exception_ctx->src_ctx.line);

        print_stack_trace();
        throw(errno);
    }
}
#endif

#if 0

void bomb_msg(int x) {

    if (x < 0) {
        int y = 123;
        throw(-1, &y);
    }

    bomb_msg(x - 1);
}


void stack_throw_check() {

    int* y;
    try {
        bomb_msg(10);
    } catch(errno, y) {
        printf("code: %d, msg: %d\n", errno, *y);
    }
}

int main() {

    stack_throw_check();
}

#endif