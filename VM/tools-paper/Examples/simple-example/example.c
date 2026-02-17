// example.c

//  stubs para c2bc / Binsec
void __VERIFIER_error(void) {
    // Error
}

/* 2 variables symboliques
 * so binsec can see different values for A and B  */
volatile int __VERIFIER_nondet_slot_a;
volatile int __VERIFIER_nondet_slot_b;
__attribute__((noinline)) int __VERIFIER_nondet_int_a(void) { return __VERIFIER_nondet_slot_a; }
__attribute__((noinline)) int __VERIFIER_nondet_int_b(void) { return __VERIFIER_nondet_slot_b; }

/* a and b are kept in globals so the binary exposes them directly for Binsec.
 * They are public (no control) variables, mirroring the nondet fuel used by fun(). */
volatile int public_a;
volatile int success_flag;


void reach_error(void) {
    __VERIFIER_error();
}

__attribute__((noinline)) void reach_success(void) {
    success_flag = 1;
}

void fun(void) {
    if (public_a != 3) {
        reach_error();
    } else {
        void (*volatile succ)(void) = reach_success;
        succ();
    }

}
int main(void) {
    /* initialize public globals before calling the sensitive function */
    public_a = __VERIFIER_nondet_int_a();
    fun();
    return 0;
}
