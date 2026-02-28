/*
 * Candidate 3 (insecure, range-policy friendly):
 * - one secret-dependent branch
 * - one secret-dependent table access only on one branch
 *
 * Expected CHECKCT baseline: insecure
 * Expected meaningful policy: (secret_k & 0x0f) < 8
 */
#include <stdint.h>

volatile uint32_t public_x;
volatile uint32_t secret_k;
volatile uint8_t lut[16] = {
    3, 11, 7, 13, 2, 17, 19, 5,
    23, 29, 31, 37, 41, 43, 47, 53
};

int main(void) {
    uint32_t x = public_x & 0xff;
    uint32_t k = secret_k & 0x0f;
    uint32_t acc = x;

    /* Secret branch: for k >= 8 we leak via secret-indexed memory access. */
    if (k < 9) {
        acc += 1;
    } else {
        acc += lut[k];
    }

    return (int)(acc & 0xff);
}
