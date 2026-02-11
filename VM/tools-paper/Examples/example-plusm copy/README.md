# Simple Example: a < b triggers error

## Goal
Show the pipeline C → c2bc → Binsec → PyAbduce on a slightly different predicate: the error is reachable when `a < b`.

## Program (`example.c`)
- `__VERIFIER_error()` marks the error location.
- `__VERIFIER_nondet_int()` provides two symbolic inputs `a` and `b`.
- The core condition is `if (a < b) reach_error();`.

## How to run
```bash
cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper
source venv/bin/activate
export PATH=~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/safety:$PATH
   # directory containing the binsec binary/AppImage / tools-paper
cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples/example-plusm/example.dir
pyabduce \
  --binsec-config example.binsec.config \
  --binsec-memory example.binsec.memory \
  --binsec-binary example.bin \
  --binsec-addr 0x80498b4 \
  --binsec-directives example.abd.directives.txt \
  --binsec-timeout 10 \
  --literals example.abd.literals.txt \
  --with-inequalities \
  --max-depth 0 \ 
  --vexamples-init-count 0

```
This will generate artifacts under `example.dir/` and invoke PyAbduce via `example.dir/example.abduce-run.bash`.

## Expected abductive constraint
In the abduction log (`example.dir/example.abduce-binsec.log`), you should see a sufficient condition involving an inequality between the two symbolic registers (e.g., something equivalent to `a < b`).

cd example.dir

pyabduce \
  --binsec-config example.binsec.config \
  --binsec-memory example.binsec.memory \
  --binsec-binary example.bin \
  --binsec-addr 0x80498b4 \
  --binsec-directives example.abd.directives.txt \
  --binsec-timeout 60 \
  --literals example.abd.literals.txt \
  --with-inequalities
