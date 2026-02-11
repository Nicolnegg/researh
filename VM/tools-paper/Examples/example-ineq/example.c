
// Examples/example-ineq/example.c
void __VERIFIER_error(void) {}

/* 2 variables symboliques
 * so binsec can see different values for A and B  */
volatile int __VERIFIER_nondet_slot_a;
volatile int __VERIFIER_nondet_slot_b;
__attribute__((noinline)) int __VERIFIER_nondet_int_a(void) { return __VERIFIER_nondet_slot_a; }
__attribute__((noinline)) int __VERIFIER_nondet_int_b(void) { return __VERIFIER_nondet_slot_b; }

void reach_error(void) { __VERIFIER_error(); }

void fun(int a, int b) {
    if (a >= b) reach_error();
}

int main(void) {
    int a = __VERIFIER_nondet_int_a();
    int b = __VERIFIER_nondet_int_b();
    fun(a, b);
    return 0;
}
