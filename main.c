#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include "cexcept.h"
#include <string.h>

int main(int argc, char* argv[]) {

    try {

        int fd = open("./hello.txt", O_CREAT | O_RDWR, 0666);

        char data[1024];
        pid_t pid = getpid();

        int len = snprintf(data, sizeof(data), "Hello, World! My PID is: %d\n", pid);
        write(fd, data, len);

    } catch(errno) {
        perror("Error");
    }
}

#if 0
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
        printf("fact(5) = %d\n", fact(5));

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