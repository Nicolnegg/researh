
extern void __attribute__ ((noinline)) c2bc_abort(void);
extern void __attribute__ ((noinline)) c2bc_assert_fail(const char* p1, const char* p2, unsigned int p3, const char* p4);
extern int c2bc_main(void);
extern void reach_error();
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

volatile int public_a;
volatile int success_flag;
void reach_success(void)
{
  success_flag = 1;
}

void fun(void)
{
  if (public_a != 3)
  {
    reach_error();
  }
  else
  {
    void (* volatile succ)(void) = reach_success;
    succ();
  }
}

int c2bc_main(void)
{
  public_a = __VERIFIER_nondet_int_a();
  fun();
  return 0;
}

