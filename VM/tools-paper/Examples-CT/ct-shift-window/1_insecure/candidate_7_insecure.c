/*
 * Candidate 7 (insecure): shift-based secret branch + secret-indexed table
 * leak on one side.
 *
 * Leak condition:
 *   k = secret_k & 0x0f
 *   (k >> 2) == 3   <=>   k in {12,13,14,15}
 *
 * Expected CHECKCT baseline: insecure
 */
#include <stdint.h>

volatile uint32_t secret_k;
volatile uint32_t public_x;
volatile uint32_t lut[16];

int main(void) {
    uint32_t k = secret_k & 0x0f;
    uint32_t x = public_x & 0xff;
    uint32_t acc = x;

    if ((k >> 2) == 3) {
        /* secret-dependent memory access (k in 12..15) */
        acc += lut[k];
    } else {
        acc += 2;
    }

    return (int)(acc & 0xff);
}
