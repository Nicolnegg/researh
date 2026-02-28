#include <stdint.h>

volatile int32_t secret_in0;
volatile int32_t secret_in1;
volatile int32_t secret_in2;
volatile int32_t public_tag;

static int sort2(int *out2, int *in2) {
    int a = in2[0];
    int b = in2[1];
    if (a < b) {
        out2[0] = in2[0];
        out2[1] = in2[1];
    } else {
        out2[0] = in2[1];
        out2[1] = in2[0];
    }
    return (a < b);
}

static void sort3(int *conds, int *out3, int *in3) {
    conds[0] = sort2(out3, in3);
    in3[1] = out3[1];
    conds[1] = sort2(out3 + 1, in3 + 1);
    in3[0] = out3[0];
    in3[1] = out3[1];
    conds[2] = sort2(out3, in3);
}

int main(void) {
    int conds[3] = {0, 0, 0};
    int out[3] = {0, 0, 0};
    int in[3];

    in[0] = (int)secret_in0;
    in[1] = (int)secret_in1;
    in[2] = (int)secret_in2;

    sort3(conds, out, in);
    return conds[0] ^ conds[1] ^ conds[2] ^ out[0] ^ out[1] ^ out[2] ^ (int)public_tag;
}
