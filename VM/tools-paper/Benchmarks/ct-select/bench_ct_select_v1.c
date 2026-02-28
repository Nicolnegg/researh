#include <stdbool.h>
#include <stdint.h>

volatile uint32_t public_x;
volatile uint32_t public_y;
volatile uint8_t secret_bit;

static int ct_isnonzero_u32(uint32_t x) {
    return (int)((x | (uint32_t)(-((int32_t)x))) >> 31);
}

static uint32_t ct_mask_u32(uint32_t bit) {
    return (uint32_t)(-ct_isnonzero_u32(bit));
}

static uint32_t ct_select_u32_v1(uint32_t x, uint32_t y, bool bit) {
    uint32_t m = ct_mask_u32((uint32_t)bit);
    return (x & m) | (y & ~m);
}

int main(void) {
    uint32_t x = public_x;
    uint32_t y = public_y;
    bool bit = (bool)(secret_bit & 1u);
    return (int)ct_select_u32_v1(x, y, bit);
}
