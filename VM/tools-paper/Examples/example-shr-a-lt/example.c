#include <stdint.h>

void __VERIFIER_error(void) {}

volatile int __VERIFIER_nondet_slot_a;
__attribute__((noinline)) int __VERIFIER_nondet_int_a(void) { return __VERIFIER_nondet_slot_a; }

volatile uint32_t public_a;
volatile int success_flag;

void reach_error(void) { __VERIFIER_error(); }
__attribute__((noinline)) void reach_success(void) { success_flag = 1; }

void fun(void) {
    if ((public_a >> 3) < 5U) {
        reach_error();
    } else {
        reach_success();
    }
}

int main(void) {
    public_a = (uint32_t)__VERIFIER_nondet_int_a();
    fun();
    return 0;
}
