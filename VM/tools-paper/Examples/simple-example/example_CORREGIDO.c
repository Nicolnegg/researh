// example_CORREGIDO.c
// ===== DIFERENCIAS CLAVE DEL ORIGINAL =====
// 1. Uso de volatile para forzar lecturas de memoria
// 2. Funciones SEPARADAS para cada valor no-determinístico
// 3. __attribute__((noinline)) para evitar optimizaciones
// 4. Esto previene que el compilador asuma que devuelven lo mismo

void __VERIFIER_error(void) {}

// ===== PATRÓN CORRECTO: Slots volátiles + funciones separadas =====
volatile int __VERIFIER_nondet_slot_a;
volatile int __VERIFIER_nondet_slot_b;

__attribute__((noinline)) 
int __VERIFIER_nondet_int_a(void) { 
    return __VERIFIER_nondet_slot_a; 
}

__attribute__((noinline)) 
int __VERIFIER_nondet_int_b(void) { 
    return __VERIFIER_nondet_slot_b; 
}

void reach_error(void) { 
    __VERIFIER_error(); 
}

void fun(int a, int b) {
    if (a == b) {
        reach_error();
    }
}

int main(void) {
    // USO: Funciones SEPARADAS en lugar de la misma función
    int a = __VERIFIER_nondet_int_a();
    int b = __VERIFIER_nondet_int_b();
    fun(a, b);
    return 0;
}
