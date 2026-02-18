/*
 * Candidate 2 (secure in this toy model): branchless masking
 * Expected CHECKCT result: secure
 */
volatile int public_a;
volatile int secret_b;

int main(void) {
    int a = public_a;
    int b = secret_b;

    unsigned int ub = (unsigned int)b;
    unsigned int sign_mask = (unsigned int)-(int)(ub >> 31); /* 0xffffffff when b < 0, else 0 */

    return a & (int)(~sign_mask);
}
