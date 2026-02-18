/*
 * Candidate 1 (insecure): secret-dependent branch
 * Expected CHECKCT result: insecure
 */
volatile int public_a;
volatile int secret_b;

int main(void) {
    int a = public_a;
    int b = secret_b;

    if (b > 7) {
        return a;
    } else {
        return b;
    }
}
