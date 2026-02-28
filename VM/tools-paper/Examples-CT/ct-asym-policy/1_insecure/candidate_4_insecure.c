/*
 * Candidate 4 (insecure, asymmetric):
 * - secret-dependent branch on k = secret_k & 0x0f
 * - branch k <= 7 is intentionally constant-time
 * - branch k > 7 performs a secret-indexed LUT access (memory leak)
 *
 * Expected baseline CHECKCT: insecure.
 * Expected useful policy shape: k <= 7 (or equivalent).
 */
#include <stdint.h>

volatile uint32_t public_x;
volatile uint32_t secret_k;
volatile uint8_t lut_bad[16] = {
    3, 11, 7, 13, 2, 17, 19, 5,
    23, 29, 31, 37, 41, 43, 47, 53
};

int main(void) {
    uint32_t x = public_x;
    uint32_t k = secret_k & 0x0f;
    uint32_t acc = x & 0xff;

    if (k <= 12) {
        /* secure side: only public/constant operations */
        acc += 0x33;
        acc ^= (x >> 1) & 0x7f;
    } else {
        /* insecure side: memory access depends on secret */
        acc += lut_bad[k];
    }

    return (int)(acc & 0xff);
}

