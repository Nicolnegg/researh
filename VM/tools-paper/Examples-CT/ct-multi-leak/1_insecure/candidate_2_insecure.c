/*
 * Candidate 2 (insecure, harder):
 * - multiple secret-dependent control-flow branches
 * - secret-dependent memory accesses (table lookups)
 * Expected CHECKCT result: insecure
 */
#include <stdint.h>

volatile uint32_t public_x;
volatile uint32_t secret_k;
volatile uint8_t lut[16] = {
    3, 11, 7, 13, 2, 17, 19, 5,
    23, 29, 31, 37, 41, 43, 47, 53
};

int main(void) {
    uint32_t x = public_x;
    uint32_t k = secret_k & 0x0f;
    uint32_t acc = x & 0xff;

    // branch depends on secret_k
    if (k > 7) {
        // memory access index depends on secret_k
        acc += lut[k];
    } else {
        acc += lut[15 - k];
    }

    // second secret-dependent branch
    if ((k & 1) == 0) {
        // Second secret-dependent memory access 
        acc ^= lut[(k + 3) & 0x0f];
    } else {
        acc ^= lut[(k + 5) & 0x0f];
    }

    return (int)(acc & 0xff);
}
