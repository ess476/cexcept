#ifndef CEXCEPT_CEXCEPT_H
#define CEXCEPT_CEXCEPT_H

#include <setjmp.h>
#include <errno.h>
#include <stdlib.h>

typedef struct __exception_ctx {
    jmp_buf jmp_ctx;
    struct __exception_ctx* prev;
    struct __exception_ctx* next;
    int code;
    int active;
    int from;
    void* obj;
} __exception_ctx_t;

__exception_ctx_t* __exception_cur_ctx;
__exception_ctx_t* __exception_tmp_ctx;

volatile int __exception_depth = 0;

volatile int __exception_ret = 1;

#define __exception_exit(code) do { exit(code); } while(0)

void __exception_handler_dfl(int code) {
    printf("global exception handler: %d\n", code);
    __exception_exit(code);
}

#define CEXCEPT_DFL = __exception_handler_dfl;

void (*__exception_handler)(int) = __exception_handler_dfl;

void cxecpt_handler(void (*handler)(int)) {
    __exception_handler = handler;
}


#define __exception_pop() \
     if (__exception_cur_ctx->active) { \
    __exception_depth--; \
    __exception_cur_ctx->active = 0; \
    __exception_tmp_ctx = __exception_cur_ctx; \
    __exception_cur_ctx = __exception_cur_ctx->prev; \
    }


void __exception_out_of_scope(__exception_ctx_t* ctx) {
    if (ctx->active) {
        __exception_pop();
    }
}

#define try { \
    __exception_tmp_ctx = __exception_cur_ctx; \
    __exception_ctx_t __attribute__((cleanup (__exception_out_of_scope))) tmp; \
    __exception_cur_ctx = &tmp; \
    __exception_cur_ctx->code = 0; \
    __exception_cur_ctx->active = 1; \
    __exception_cur_ctx->from = __LINE__; \
    __exception_cur_ctx->obj = NULL; \
    __exception_cur_ctx->prev = __exception_tmp_ctx; \
    __exception_cur_ctx->next = NULL; \
    if (__exception_tmp_ctx) { \
        __exception_tmp_ctx->next = __exception_cur_ctx; \
    } \
    __exception_depth++; \
    if ((__exception_ret = setjmp(__exception_cur_ctx->jmp_ctx)) == 0)

#define throw1(__code) \
    do { \
        if (__exception_depth) { \
            __exception_pop(); \
            __exception_tmp_ctx->code = __code; \
            __exception_tmp_ctx->obj = NULL; \
            longjmp(__exception_tmp_ctx->jmp_ctx, 1); \
        } else { \
            __exception_handler(__code); \
        } \
    } while(0)

#define throw2(__code, __obj) \
    do { \
        if (__exception_depth) { \
            __exception_pop(); \
            __exception_tmp_ctx->code = __code; \
            __exception_tmp_ctx->obj = (void*) __obj; \
            longjmp(__exception_tmp_ctx->jmp_ctx, 1); \
        } else { \
            __exception_handler(__code); \
        } \
    } while(0)

#define GET_THROW_MACRO(_1, _2, NAME, ...) NAME
#define throw(...) GET_THROW_MACRO(__VA_ARGS__, throw2, throw1)(__VA_ARGS__)

#define catch0() \
    } if (!__exception_ret) { \
    } else if (((errno = __exception_tmp_ctx->code) || 1) && !(__exception_ret = 0))

#define catch1(__code) \
    } if (!__exception_ret) { \
    } else if (((__code = __exception_tmp_ctx->code) || 1) && !(__exception_ret = 0))

#define catch2(__code, __obj) \
    } __obj = NULL; \
    if (!__exception_ret) { \
    } else if ((((__code = __exception_tmp_ctx->code) && (__obj = __exception_tmp_ctx->obj)) || 1) && !(__exception_ret = 0))


#define GET_CATCH_MACRO(_0, _1, _2, NAME, ...) NAME
#define catch(...) GET_CATCH_MACRO(_0, ##__VA_ARGS__, catch2, catch1, catch0)(__VA_ARGS__)

#endif //CEXCEPT_CEXCEPT_H
