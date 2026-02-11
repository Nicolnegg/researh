
#define __attribute__(x)
#define __extension__
#define __inline
#define __restrict
#define __const
#include <stdint.h>

volatile int elm = 0;
volatile int errc = 0;

static char safety = 0x01;

void __VERIFIER_error(void) {}

void reach_error(void) { __VERIFIER_error(); }

int __attribute__ ((noinline)) fail(int v) {
    errc = v;
    reach_error();
    return v;
}

char __attribute__ ((noinline)) read_input(void) {
    return (char)elm;
}

int main(void) {
    char input;
    input = read_input();
    if (input == 0) {
        fail(1);
    }
    return 0;
}

