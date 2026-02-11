
extern void reach_error();
extern void __attribute__ ((noinline)) c2bc_assert_fail(const char* p1, const char* p2, unsigned int p3, const char* p4);
extern int c2bc_main(void);
extern void __attribute__ ((noinline)) c2bc_abort(void);
void __VERIFIER_error(void)
{
}

volatile int __VERIFIER_nondet_slot_a;
volatile int __VERIFIER_nondet_slot_b;
int __VERIFIER_nondet_int_a(void)
{
  return __VERIFIER_nondet_slot_a;
}

int __VERIFIER_nondet_int_b(void)
{
  return __VERIFIER_nondet_slot_b;
}

void fun(int a, int b)
{
  if (a < b)
    reach_error();
}

int c2bc_main(void)
{
  int a = __VERIFIER_nondet_int_a();
  int b = __VERIFIER_nondet_int_b();
  fun(a, b);
  return 0;
}

