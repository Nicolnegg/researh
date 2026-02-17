void __VERIFIER_error(void) {}

/* Provide two independent symbolic slots and advance an index so the two calls
 * in main use different symbolic values. This prevents the compiler from
 * folding them into a single load. */
static volatile int __VERIFIER_nondet_slots[2];
static int __VERIFIER_nondet_idx = 0;
__attribute__((noinline))
int __VERIFIER_nondet_int(void) {
    int v = __VERIFIER_nondet_slots[__VERIFIER_nondet_idx & 1];
    __VERIFIER_nondet_idx++;
    return v;
}
volatile int success_flag;

void reach_error(void) { __VERIFIER_error(); }
__attribute__((noinline)) void reach_success(void) { success_flag = 1; }

void fun(int a, int b) {
    if (a > b) {
        reach_error();
    } else {
        reach_success();
    }
}

int main(void) {
    int a = __VERIFIER_nondet_int();
    /* Force b > a to make reach_error reachable deterministically. */
    int b = a + 1;
    fun(a, b);
    return 0;
}
