# ----------------------------------------
CoreBinsecConfig = """
[kernel]
isa = x86
entrypoint = {}
[x86]
protected-mode = true
[sse]
enabled = true
depth = 10000
directives = {}
"""
# ----------------------------------------
StandardBinsecConfig = CoreBinsecConfig + """
#robust = true
#robust-merge = yes
#robust-mode = validation
ignore-controlled = true
[fml]
solver = z3
#universal-mode = quantifier
#unquantify-memory = true
#optim-all = true
"""
StandardBinsecMemory = """
esp<32> := 0xfff80000;
controlled dummy<32>;
"""
# ----------------------------------------
RobustBinsecConfig = CoreBinsecConfig + """
robust = true
robust-merge = yes
robust-mode = validation
[fml]
solver = z3
universal-mode = quantifier
unquantify-memory = true
optim-all = true
"""
RobustBinsecMemory = """
esp<32> := 0xfff80000;
controlled dummy<32>;
"""
# ----------------------------------------
PreprocessorParseInit = """
#define __attribute__(x)
#define __extension__
#define __inline
#define __restrict
#define __const
"""
# ----------------------------------------
StubStdlib = (
(
    'c2bc_abort',
    'extern void __attribute__ ((noinline)) c2bc_abort(void);',
"""
static unsigned int _stub_abort_counter = 0;
static unsigned int _stub_abort_cut_counter = 0;
extern unsigned int _stub_abort_counter;
extern unsigned int _stub_abort_cut_counter;
extern void __attribute__ ((noinline)) c2bc_abort(void) {
    _stub_abort_counter += 3;
    _stub_abort_cut_counter += 7;
}
"""
),

(
    'c2bc_exit',
    'extern void c2bc_exit(int status);',
"""
extern void c2bc_exit(int status) { c2bc_abort(); }
""",
    'c2bc_abort'
),

(
    '__VERIFIER_assert',
    'extern void __VERIFIER_assert(int cond);',
"""
extern void __VERIFIER_assert(int cond) { if(!(cond)) { ERROR: {reach_error();c2bc_abort();} } }
""",
    'reach_error',
    'c2bc_abort'
),

(
    'reach_error',
    'extern void reach_error();',
"""
extern void reach_error() { c2bc_assert_fail("stub-induced", "stub-induced", 3, "reach_error"); }
""",
    'c2bc_assert_fail'
),

(
    'c2bc_assert_fail',
    'extern void __attribute__ ((noinline)) c2bc_assert_fail(const char* p1, const char* p2, unsigned int p3, const char* p4);',
"""
static unsigned int _stub_failure_counter = 0;
extern unsigned int _stub_failure_counter;
static unsigned int _stub_failure_cut_counter = 0;
extern unsigned int _stub_failure_cut_counter;
extern void __attribute__ ((noinline)) c2bc_assert_fail(const char* p1, const char* p2, unsigned int p3, const char* p4) {
    _stub_failure_counter += 3;
    _stub_failure_cut_counter += 7;
}
"""
),

(
    'c2bc_assert',
    'extern void c2bc_assert(int c);',
"""
extern void c2bc_assert(int c) {
    if (c) {;} else {
        c2bc_assert_fail("here", "here", 1, "");
    }
}
""",
    'c2bc_assert_fail'
),

(
    'c2bc_malloc',
    'extern void* c2bc_malloc(unsigned int size);',
"""
#define _STUB_MALLOC_MAXSIZE 1024
static unsigned int _stub_malloc_index = 0;
extern unsigned int _stub_malloc_index;
static char _stub_malloc_data[_STUB_MALLOC_MAXSIZE] = {0};
extern char _stub_malloc_data[_STUB_MALLOC_MAXSIZE];
extern void* c2bc_malloc(unsigned int size) {
    unsigned int res = _stub_malloc_index;
    _stub_malloc_index += size;
    return &(_stub_malloc_data[_stub_malloc_index]);
}
"""
),

(
    'c2bc_calloc',
    'extern void* c2bc_calloc(unsigned int num, unsigned int size);',
"""
extern void* c2bc_calloc(unsigned int num, unsigned int size) {
    void * ptr = c2bc_malloc(num*size);
    for (unsigned int i = 0; i < num*size ; i++) {
        ((unsigned char*)ptr)[i] = (unsigned char)0;
    }
    return ptr;
}
""",
    'c2bc_malloc'
),

(
    'nondet_pointer',
    'extern int nondet_pointer();',
"""
extern int nondet_pointer() {
        c2bc_abort(); return 0;
}
""",
    'c2bc_abort'
),

(
    'c2bc_free',
    'extern void c2bc_free(void* ptr);',
"""
extern void c2bc_free(void* ptr) {}
"""
),

(
    'c2bc_write',
    'extern signed long int c2bc_write(int fd, const void* buf, unsigned long int nbytes);',
"""
extern signed long int c2bc_write(int fd, const void* buf, unsigned long int nbytes) { return nbytes; }
"""
),

(
    'c2bc_read',
    'extern signed long int c2bc_read(int fd, const void* buf, unsigned long int count);',
"""
#define _STUB_READ_MAXSIZE 1024
static unsigned int _stub_read_index = 0;
extern unsigned int _stub_read_index;
static char _stub_read_data[_STUB_READ_MAXSIZE] = {0};
extern char _stub_read_data[_STUB_READ_MAXSIZE];
extern signed long int c2bc_read(int fd, const void* buf, unsigned long int count) {
    signed long int rc = 0;
    char* cbuf = (char*)buf;
    while (count > 0 && _stub_read_index < _STUB_READ_MAXSIZE) {
        cbuf[rc++] = _stub_read_data[_stub_read_index++];
        count--;
    }
    return rc;
}
"""
),

(
    'c2bc_memset',
    'extern void* c2bc_memset(void* ptr, int value, unsigned long int num);',
"""
extern void* c2bc_memset(void* ptr, int value, unsigned long int num) {
    unsigned char* p = ptr;
    while(num--) *p++ = (unsigned char)value;
    return ptr;
}
"""
),

(
    'c2bc_memmove',
    'extern void* c2bc_memmove(void* dest, const void* src, unsigned long int count);',
"""
extern void* c2bc_memmove(void* dest, const void* src, unsigned long int count) {
    // source: STEXH 174935
    unsigned char* d = dest;
    const unsigned char* s = src;
    if (s < d) { s+= count; d += count;
        while (count--) *--d = *--s;
    } else {
        while (count--) *d++ = *s++;
    }
    return dest;
}
"""
),

(
    'c2bc_memcpy',
    'extern void c2bc_memcpy(void* dest, void* src, unsigned long int n);',
"""
extern void c2bc_memcpy(void* dest, void* src, unsigned long int n) {
    // source: GFG
    unsigned char* csrc = src;
    unsigned char* cdest = dest;
    for (int i = 0; i < n ; i++)
        cdest[i] = csrc[i];
}
"""
),

(
    'c2bc_memcmp',
    'extern int c2bc_memcmp (const void *str1, const void *str2, unsigned long int count);',
"""
extern int c2bc_memcmp (const void *str1, const void *str2, unsigned long int count) {
    // source: gcc
    const unsigned char *s1 = (const unsigned char*)str1;
    const unsigned char *s2 = (const unsigned char*)str2;

    while (count-- > 0)
        if (*s1++ != *s2++)
            return s1[-1] < s2[-1] ? -1 : 1;
    return 0;
}
"""
),

(
    'c2bc_printf',
    'extern int c2bc_printf(char const   * __restrict  __format  , ...) ;',
"""
extern int c2bc_printf(char const   * __restrict  __format  , ...)  { return 0; }
"""
),

(
    'c2bc_puts',
    'extern int c2bc_puts(const char * str);',
"""
extern int c2bc_puts(const char * str) { return 0; }
"""
),

(
    'LARGE_INT',
    'extern int LARGE_INT;',
"""
int LARGE_INT = 0x100ff;
"""
),

(
    'c2bc_bss_exhibiter_keystring',
    'extern int c2bc_bss_exhibiter_keystring;',
"""
int c2bc_bss_exhibiter_keystring = 0x3f412216a;
"""
),

(
    'main',
    'extern int c2bc_main(void);',
"""
static int _main_hook = 0;
extern int _main_hook;
int main(void) {
    int res = c2bc_main();
    c2bc_abort();
    _main_hook += 7;
    return res;
}
""",
    'c2bc_abort'
),
)
# ----------------------------------------
NondetStubTemplate = (
    '__VERIFIER_nondet_{}',
    'extern {1}{2} __VERIFIER_nondet_{0}(void);',
"""
#define _STUB_{0}_ARRAY_SIZE 1024
static unsigned int _stub_{0}_index = 0;
extern unsigned int _stub_{0}_index;
static {1} _stub_{0}_array[_STUB_{0}_ARRAY_SIZE] = {{0}};
extern {1} _stub_{0}_array[_STUB_{0}_ARRAY_SIZE];
extern {1}{2} __VERIFIER_nondet_{0}(void) {{
    if (_stub_{0}_index < _STUB_{0}_ARRAY_SIZE) {{
        return {3}(_stub_{0}_array[_stub_{0}_index++]);
    }} else {{
        c2bc_abort(); return 0;
    }}
}}
""",
    'c2bc_abort'
)
# ----------------------------------------
class Stub:
    
    def __init__(self, ident, fdecl, fdef, deps):
        self.identifier = ident
        self.declaration = fdecl
        self.definition = fdef
        self.depends = deps
# ----------------------------------------
def typeudt1(tname):
    return '*' if tname.endswith('pointer') or tname.endswith('p') else ''
def typeudt2(tname):
    return '&' if tname.endswith('pointer') or tname.endswith('p') else ''
# ----------------------------------------
StubNondetlib = tuple(
    (
        NondetStubTemplate[0].format(ntype),
        NondetStubTemplate[1].format(ntype, rtype, typeudt1(ntype)),
        NondetStubTemplate[2].format(ntype, rtype, typeudt1(ntype), typeudt2(ntype)),
        NondetStubTemplate[3]
    )
    for ntype, rtype in (
        ('uint', 'unsigned int'),
        ('int', 'int'),
        ('short', 'short'),
        ('ushort', 'unsigned short'),
        ('long', 'long'),
        ('ulong', 'unsigned long'),
        ('char', 'char'),
        ('uchar', 'unsigned char'),
        ('unsigned_char', 'unsigned char'),
        ('float', 'float'),
        ('double', 'double'),
        ('bool', '_Bool'),

        ('const_char_pointer', 'const char'),
        ('charp', 'char'),
    )
)
# ----------------------------------------
def stubs():
    stubs = dict()
    for stubdata in StubStdlib + StubNondetlib:
        ident = stubdata[0]
        fdecl = stubdata[1]
        fdef  = stubdata[2]
        deps  = set()
        for index in range(3, len(stubdata)):
            deps.add(stubdata[index])
        stubs[ident] = Stub(ident, fdecl, fdef, deps)
    return stubs
# ----------------------------------------
# ----------------------------------------
