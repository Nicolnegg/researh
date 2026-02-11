
extern int c2bc_main(void);
extern void reach_error();
extern void __attribute__ ((noinline)) c2bc_assert_fail(const char* p1, const char* p2, unsigned int p3, const char* p4);
extern void __attribute__ ((noinline)) c2bc_abort(void);
void __VERIFIER_error(void)
{
}

static volatile int __VERIFIER_nondet_slots[2];
static int __VERIFIER_nondet_idx = 0;
int __VERIFIER_nondet_int(void)
{
  int v = __VERIFIER_nondet_slots[__VERIFIER_nondet_idx & 1];
  __VERIFIER_nondet_idx++;
  return v;
}

void fun(int a, int b)
{
  if (a > b)
    reach_error();
}

int c2bc_main(void)
{
  int a = __VERIFIER_nondet_int();
  int b = a + 1;
  fun(a, b);
  return 0;
}

