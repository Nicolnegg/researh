#include <stdbool.h>
#include <stdint.h>

volatile uint32_t public_x;
volatile uint32_t public_y;
volatile uint8_t secret_bit;

static uint32_t ct_select_u32_naive(uint32_t x, uint32_t y, bool bit) {
    return bit ? x : y;
}

int main(void) {
    uint32_t x = public_x;
    uint32_t y = public_y;
    bool bit = (bool)(secret_bit & 1u);
    return (int)ct_select_u32_naive(x, y, bit);
}
