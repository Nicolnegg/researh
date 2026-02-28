#ifndef LIBSYM_SYM_H
#define LIBSYM_SYM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Minimal local stubs for benchmarks.
 * They keep benchmark sources buildable when libsym is not shipped.
 */
static inline void high_input_1(void *p) {
    (void)p;
}

static inline void low_input_4(void *p) {
    (void)p;
}

static inline void high_input_12(void *p) {
    (void)p;
}

#ifdef __cplusplus
}
#endif

#endif
