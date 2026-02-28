
#include <stdint.h>

volatile uint32_t public_x;
volatile uint32_t secret_k;
volatile uint8_t lut_a[16] = {
    3, 11, 7, 13, 2, 17, 19, 5,
    23, 29, 31, 37, 41, 43, 47, 53
};
volatile uint8_t lut_b[16] = {
    59, 61, 67, 71, 73, 79, 83, 89,
    97, 101, 103, 107, 109, 113, 127, 131
};

int main(void) {
    uint32_t x = public_x & 0xff;
    uint32_t k = secret_k & 0x0f;
    uint32_t acc = x;

    if ((k >= 3) && (k <= 10)) {
        /* secure region B */
        acc ^= (x >> 1) & 0x3f;
    } else if ((k == 12) || (k == 14)) {
        /* secure region C */
        acc += 0x17;
    } else {
        /* insecure region: secret-dependent memory accesses */
        acc += lut_a[k];
        acc ^= lut_b[(k + 3) & 0x0f];
    }

    return (int)(acc & 0xff);
}

