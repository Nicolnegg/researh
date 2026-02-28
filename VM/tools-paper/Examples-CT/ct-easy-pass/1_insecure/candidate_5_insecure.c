/*
 * Candidate 5 (insecure, easy-pass):
 * - secret-dependent branch on secret_b
 * - insecure branch performs secret-indexed memory access
 *
 * Baseline is insecure.
 * Expected policy shape: secret_b = 0x00 (or equivalent).
 */
#include <stdint.h>

volatile uint32_t public_x;
volatile uint8_t secret_b;
volatile uint8_t lut[16] = {
    3, 11, 7, 13, 2, 17, 19, 5,
    23, 29, 31, 37, 41, 43, 47, 53
};

int main(void) {
    uint8_t b = secret_b;
    uint32_t acc = public_x & 0xff;

    if (b == 0) {
        acc += 7;
    } else {
        acc += lut[b & 0x0f];
    }

    return (int)(acc & 0xff);
}

