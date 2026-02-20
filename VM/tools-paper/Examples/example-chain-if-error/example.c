void __VERIFIER_error(void) {}

volatile int __VERIFIER_nondet_slot_a;
volatile int __VERIFIER_nondet_slot_b;
volatile int __VERIFIER_nondet_slot_c;
volatile int __VERIFIER_nondet_slot_d;

__attribute__((noinline)) int __VERIFIER_nondet_int_a(void) { return __VERIFIER_nondet_slot_a; }
__attribute__((noinline)) int __VERIFIER_nondet_int_b(void) { return __VERIFIER_nondet_slot_b; }
__attribute__((noinline)) int __VERIFIER_nondet_int_c(void) { return __VERIFIER_nondet_slot_c; }
__attribute__((noinline)) int __VERIFIER_nondet_int_d(void) { return __VERIFIER_nondet_slot_d; }

volatile int success_flag;

void reach_error(void) { __VERIFIER_error(); }
__attribute__((noinline)) void reach_success(void) { success_flag = 1; }

void fun(int a, int b, int c, int d) {
    if (a > b) {
        if (b > c) {
            if (c > d) {
                if ((a - d) > 100) {
                    reach_error();
                } else {
                    reach_success();
                }
            } 
        } 
    } 
}

int main(void) {
    int a = __VERIFIER_nondet_int_a();
    int b = __VERIFIER_nondet_int_b();
    int c = __VERIFIER_nondet_int_c();
    int d = __VERIFIER_nondet_int_d();
    fun(a, b, c, d);
    return 0;
}
