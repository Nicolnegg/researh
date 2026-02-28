#include <stdint.h>

volatile int32_t secret_in0;
volatile int32_t secret_in1;
volatile int32_t secret_in2;
volatile int32_t public_tag;

static void sort2_negative(int *out2, int *in2) {
    int a = in2[0];
    int b = in2[1];
    if (a < b) {
        out2[0] = in2[0];
        out2[1] = in2[1];
    } else {
        out2[0] = in2[1];
        out2[1] = in2[0];
    }
}

static void sort3_negative(int *out3, int *in3) {
    sort2_negative(out3, in3);
    in3[1] = out3[1];
    sort2_negative(out3 + 1, in3 + 1);
    in3[0] = out3[0];
    in3[1] = out3[1];
    sort2_negative(out3, in3);
}

int main(void) {
    int out[3] = {0, 0, 0};
    int in[3];

    in[0] = (int)secret_in0;
    in[1] = (int)secret_in1;
    in[2] = (int)secret_in2;

    sort3_negative(out, in);
    return out[0] ^ out[1] ^ out[2] ^ (int)public_tag;
}
