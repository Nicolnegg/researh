#include <stdint.h>

volatile int elm = 0;
volatile int errc = 0;
volatile int success_flag = 0;

static char safety = 0x01;

void __VERIFIER_error(void) {}

void reach_error(void) { __VERIFIER_error(); }
__attribute__((noinline)) void reach_success(void) { success_flag = 1; }

int __attribute__ ((noinline)) fail(int v) {
    errc = v;
    reach_error();
    return v;
}

char __attribute__ ((noinline)) read_input(void) {
    return (char)elm;
}

int main(void) {
    unsigned char input;
    input = read_input();
    if (input == 0) {
        fail(1);
    } else {
        reach_success();
    }
    return 0;
}
