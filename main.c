#include <stdio.h>
#include "cexcept.h"

void bomb(int x) {

    if (x < 0) {
        throw(456);
    }

    bomb(x - 1);
}

int main() {

    try {
        try {

            bomb(15);

        } catch(errno) {

            printf("catch 1: %d\n", errno);
            throw(789);

        }
    } catch(errno) {
        printf("catch 2: %d\n", errno);
    }
}