/*
 * Candidate 8 (insecure): AND-mask branch + secret-indexed table leak.
 *
 * Leak condition:
 *   k = secret_k & 0x0f
 *   (k & 0x0c) == 0x0c   <=>   k in {12,13,14,15}
 *
 * This avoids shifts in the pivot and usually yields cleaner constraints.
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

    if ((k & 0x0c) == 0x0c) {
        /* secret-dependent memory access for k in 12..15 */
        acc += lut[k];
    } else {
        acc += 2;
    }

    return (int)(acc & 0xff);
}
