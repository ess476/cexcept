#ifndef CEXCEPT_CEXCEPT_H
#define CEXCEPT_CEXCEPT_H

#include <setjmp.h>
#include <errno.h>
#include <stdlib.h>

#define CEXCEPT_MAX_DEPTH 1024

jmp_buf __exception_ctx_stack[CEXCEPT_MAX_DEPTH];

volatile int __exception_depth = 0;

volatile int __exception_ret = 1;

#define __exception_exit(code) do { exit(code); } while(0)

void __exception_handler_dfl(int code) {
    printf("global exception handler: %d\n", code);
    __exception_exit(code);
}

int static inline __exception_depth_check() {
    if (__exception_depth == CEXCEPT_MAX_DEPTH) {
        __exception_exit(1);
    }

    return 1;
}

#define CEXCEPT_DFL = __exception_handler_dfl;

void (*__exception_handler)(int) = __exception_handler_dfl;

void cxecpt_handler(void (*handler)(int)) {
    __exception_handler = handler;
}

#define try if (__exception_depth_check() && (__exception_ret = setjmp(__exception_ctx_stack[__exception_depth++])) == 0)

#define throw(code) do { if (__exception_depth) {longjmp(__exception_ctx_stack[--__exception_depth], code); } else { __exception_handler(code); } } while(0)

#define catch0() else if ((errno = __exception_ret))

#define catch1(var) else if ((var = __exception_ret))

#define GET_MACRO(_0, _1, NAME, ...) NAME
#define catch(...) GET_MACRO(_0, ##__VA_ARGS__, catch1, catch0)(__VA_ARGS__)

#endif //CEXCEPT_CEXCEPT_H
