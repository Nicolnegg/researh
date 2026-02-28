# Benchmarks CT (pyabduce)

Guía exacta para correr benchmarks `ct-select` y `ct-sort` con el flujo nuevo:

`c2bc --ct` + `abduce-run.bash` (pyabduce).

## 1) Preparar entorno (una vez por terminal)

```bash
cd ~/Documentos/M2-Cyber/RESEARCH
eval $(opam env)
cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper
source venv/bin/activate
export PATH=/home/nicol/Documentos/M2-Cyber/RESEARCH/binsec/_opam/bin:$PATH
```

## 2) Correr todos los benchmarks CT

### 2.1 ct-select (todos)

```bash
cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Benchmarks/ct-select
./run_ct_abduce_all.sh --solver-timeout 120
```

### 2.2 ct-sort (todos)

```bash
cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Benchmarks/ct-sort
./run_ct_abduce_all.sh --solver-timeout 120
```

## 3) Correr un benchmark específico

### 3.1 ct-select v1

```bash
cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Benchmarks/ct-select
c2bc -i bench_ct_select_v1.c --ct --ct-secret secret_bit --ct-public public_x,public_y
./bench_ct_select_v1.dir/bench_ct_select_v1.abduce-run.bash \
  --with-inequalities \
  --policy-report bench_ct_select_v1.report.json
```

### 3.2 ct-select naive

```bash
cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Benchmarks/ct-select
c2bc -i bench_ct_select_naive.c --ct --ct-secret secret_bit --ct-public public_x,public_y
./bench_ct_select_naive.dir/bench_ct_select_naive.abduce-run.bash \
  --with-inequalities \
  --policy-report bench_ct_select_naive.report.json
```

### 3.3 ct-sort

```bash
cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Benchmarks/ct-sort
c2bc -i bench_ct_sort.c --ct --ct-secret secret_in0,secret_in1,secret_in2 --ct-public public_tag
./bench_ct_sort.dir/bench_ct_sort.abduce-run.bash \
  --with-inequalities \
  --policy-report bench_ct_sort.report.json
```

## 4) Flags útiles

```bash
--with-inequalities
--with-bitwise-terms
--with-mul-terms
--solver-timeout <segundos>
--policy-report <archivo.json>
```

Ejemplo:

```bash
./run_ct_abduce_all.sh --with-bitwise-terms --solver-timeout 180
```

## 5) Qué revisar en salida

- `checkct status: secure|insecure`
- `q_explain (prioritized): ...`
- `selected constraint: ...`
- `policy report written: ...report.json`

## 6) Importante

- Para CT + pyabduce usa wrappers `bench_ct_*.c` (no los `.c` legacy).
- `make all` en `Benchmarks` solo compila binarios legacy; no es el flujo recomendado para CT-abducer.

## 7) Agregar resultados (CSV + gráficas)

Una vez tengas reportes `*.report.json`, agrega resultados así:

```bash
cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper
python3 tools/pyabduce/scripts/ct_report_aggregate.py \
  --root . \
  --out ct-results
```

Salida:

- `ct-results/summary.csv`
- `ct-results/summary.md`
- (si hay `matplotlib`) `ct-results/*.png`
