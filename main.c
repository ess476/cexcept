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
        printf("caught exception: %d from: %s:%d\n", errno, exception_ctx->src_ctx.file, exception_ctx->src_ctx.line);


        return 1;
    }
}


int main() {


    try {
        fact(50);

        throw(12);
    } catch(errno) {
        printf("caught exception: %d from: %s:%d\n", errno, exception_ctx->src_ctx.file, exception_ctx->src_ctx.line);

        print_stack_trace();
        throw(errno);
    }
}