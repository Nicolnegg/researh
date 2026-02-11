extern void __attribute__ ((noinline)) c2bc_assert_fail(const char* p1, const char* p2, unsigned int p3, const char* p4);
extern int c2bc_main(void);
extern void __attribute__ ((noinline)) c2bc_abort(void);
extern void reach_error();
extern int c2bc_bss_exhibiter_keystring;

static unsigned int _stub_failure_counter = 0;
extern unsigned int _stub_failure_counter;
static unsigned int _stub_failure_cut_counter = 0;
extern unsigned int _stub_failure_cut_counter;
extern void __attribute__ ((noinline)) c2bc_assert_fail(const char* p1, const char* p2, unsigned int p3, const char* p4) {
    _stub_failure_counter += 3;
    _stub_failure_cut_counter += 7;
}


static int _main_hook = 0;
extern int _main_hook;
int main(void) {
    int res = c2bc_main();
    c2bc_abort();
    _main_hook += 7;
    return res;
}


static unsigned int _stub_abort_counter = 0;
static unsigned int _stub_abort_cut_counter = 0;
extern unsigned int _stub_abort_counter;
extern unsigned int _stub_abort_cut_counter;
extern void __attribute__ ((noinline)) c2bc_abort(void) {
    _stub_abort_counter += 3;
    _stub_abort_cut_counter += 7;
}


extern void reach_error() { c2bc_assert_fail("stub-induced", "stub-induced", 3, "reach_error"); }


int c2bc_bss_exhibiter_keystring = 0x3f412216a;

