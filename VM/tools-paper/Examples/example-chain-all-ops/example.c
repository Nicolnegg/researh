#include <stdint.h>

void __VERIFIER_error(void) {}

volatile int __VERIFIER_nondet_slot_a;
volatile int __VERIFIER_nondet_slot_b;
volatile int __VERIFIER_nondet_slot_c;
volatile int __VERIFIER_nondet_slot_d;

__attribute__((noinline)) int __VERIFIER_nondet_int_a(void) { return __VERIFIER_nondet_slot_a; }
__attribute__((noinline)) int __VERIFIER_nondet_int_b(void) { return __VERIFIER_nondet_slot_b; }
__attribute__((noinline)) int __VERIFIER_nondet_int_c(void) { return __VERIFIER_nondet_slot_c; }
__attribute__((noinline)) int __VERIFIER_nondet_int_d(void) { return __VERIFIER_nondet_slot_d; }

volatile uint32_t public_a;
volatile uint32_t public_b;
volatile uint32_t public_c;
volatile uint32_t public_d;
volatile int success_flag;

void reach_error(void) { __VERIFIER_error(); }
__attribute__((noinline)) void reach_success(void) { success_flag = 1; }

void fun(void) {
    uint32_t s1 = (public_a + public_b) - public_c;
    uint32_t s2 = ((public_b << 2) >> 1) + (public_d & 0x0000000fU);
    uint32_t s3 = (public_c | 0x00000030U) - (public_a & 0x00000007U);

    if ((public_a >= public_b) &&
        (s1 < 0x00000100U) &&
        (s2 >= 0x00000020U) &&
        (s3 < 0x00000120U) &&
        (((public_a & 0x000000ffU) + (public_c >> 2)) > (public_d | 0x00000001U))) {
        reach_error();
    } else {
        reach_success();
    }
}

int main(void) {
    public_a = (uint32_t)__VERIFIER_nondet_int_a();
    public_b = (uint32_t)__VERIFIER_nondet_int_b();
    public_c = (uint32_t)__VERIFIER_nondet_int_c();
    public_d = (uint32_t)__VERIFIER_nondet_int_d();
    fun();
    return 0;
}
