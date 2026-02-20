# Examples-CT

This folder contains constant-time (CT) examples validated with BINSEC `-checkct`.

## Environment setup

```bash
cd ~/Documentos/M2-Cyber/RESEARCH
eval $(opam env)

cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper
source venv/bin/activate
export PATH=/home/nicol/Documentos/M2-Cyber/RESEARCH/binsec/_opam/bin:$PATH
```

## Available CT examples

- `simple-ct-branch`: minimal demo with one insecure candidate and one secure candidate.
  - `1_insecure/candidate_1_insecure.c`
  - `1_secure/candidate_1_secure.c`
- `ct-multi-leak`: harder insecure demo with two secret branches + secret table lookups.
  - `1_insecure/candidate_2_insecure.c`

## Run with BINSEC CHECKCT

```bash
# insecure case
cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples-CT/simple-ct-branch/1_insecure
c2bc -i candidate_1_insecure.c --ct --ct-secret secret_b --ct-public public_a
binsec -sse -checkct -sse-script candidate_1_insecure.dir/candidate_1_insecure.binsec.sse \
  candidate_1_insecure.dir/candidate_1_insecure.bin

# secure case
cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples-CT/simple-ct-branch/1_secure
c2bc -i candidate_1_secure.c --ct --ct-secret secret_b --ct-public public_a
binsec -sse -checkct -sse-script candidate_1_secure.dir/candidate_1_secure.binsec.sse \
  candidate_1_secure.dir/candidate_1_secure.bin

# harder insecure case
cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples-CT/ct-multi-leak/1_insecure
c2bc -i candidate_2_insecure.c --ct --ct-secret secret_k --ct-public public_x
binsec -sse -checkct -sse-script candidate_2_insecure.dir/candidate_2_insecure.binsec.sse \
  candidate_2_insecure.dir/candidate_2_insecure.bin
```

Expected CHECKCT summary:

- `candidate_1_insecure`: `Program status is : insecure`
- `candidate_1_secure`: `Program status is : secure`
- `candidate_2_insecure`: `Program status is : insecure` (usually with multiple leaks)

## Run with pyabduce (CT mode)

The generated `*.abduce-run.bash` already forwards `--ct-mode` automatically when built with `c2bc --ct`.

```bash
# insecure case
cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples-CT/simple-ct-branch/1_insecure
c2bc -i candidate_1_insecure.c --ct --ct-secret secret_b --ct-public public_a
./candidate_1_insecure.dir/candidate_1_insecure.abduce-run.bash --with-inequalities

./candidate_1_insecure.dir/candidate_1_insecure.abduce-run.bash \
  --with-inequalities \
  --collect-until-timeout \
  --solver-timeout 10 \
  --policy-report candidate_1_insecure.collect.report.json -> more candidate

  ./candidate_1_insecure.dir/candidate_1_insecure.abduce-run.bash --with-inequalities --selection-mode size-complexity --policy-report candidate_1_insecure.report.json

./candidate_1_insecure.dir/candidate_1_insecure.abduce-run.bash \
  --with-inequalities \
  --selection-mode branch-first \
  --policy-report candidate_1_insecure.report.json



# secure case
cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples-CT/simple-ct-branch/1_secure
c2bc -i candidate_1_secure.c --ct --ct-secret secret_b --ct-public public_a
./candidate_1_secure.dir/candidate_1_secure.abduce-run.bash \
  --with-inequalities
```

Expected pyabduce behavior:

- insecure case:
  - logs `checkct status: insecure`
  - logs leaks as `checkct leak: Instruction ... has ... leak`
  - finds at least one non-trivial sufficient condition
- secure case:
  - candidate `set()` is accepted as solution
  - final NAS condition is `set()`

## Deterministic Policy Selection + JSON report

`pyabduce` now computes a deterministic selected policy (then alternatives), runs
final CT validation (`baseline` vs `selected`), and can export a JSON report.

```bash
cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples-CT/simple-ct-branch/1_insecure

c2bc -i candidate_1_insecure.c --ct --ct-secret secret_b --ct-public public_a

./candidate_1_insecure.dir/candidate_1_insecure.abduce-run.bash \
  --policy-report candidate_1_insecure.report.json
```

Expected terminal lines:

- `selected policy: {...}`
- `policy report written: .../candidate_1_insecure.report.json`

Inspect report:

```bash
cat candidate_1_insecure.report.json
```

Minimal fields:

- `ct_validation.baseline.status` (expected `insecure`)
- `ct_validation.selected.status` (expected `secure`)
- `selected_policy`
- `alternatives`
- `stats`

### Collect multiple NAS until timeout

To keep searching after the first NAS and return all NAS found before a time budget:

```bash
cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples-CT/simple-ct-branch/1_insecure

./candidate_1_insecure.dir/candidate_1_insecure.abduce-run.bash \
  --with-inequalities \
  --collect-until-timeout \
  --solver-timeout 2 \
  --policy-report candidate_1_insecure.collect.report.json
```

Expected:

- warning when timeout is reached: `solver timeout reached (...)`
- final `nas conditions (all)` contains one or more policies
- JSON report includes `selected_policy` and `alternatives`

## Reproducible / paper runs

For stable research runs:

- keep same machine and same toolchain (`opam`, BINSEC build)
- force deterministic Python hash seed (`PYTHONHASHSEED=0`)
- avoid early cutoff for main paper numbers (`--paper-mode`)

```bash
cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples-CT/simple-ct-branch/1_insecure

# regenerate runner (new runners set PYTHONHASHSEED=0 by default)
c2bc -i candidate_1_insecure.c --ct --ct-secret secret_b --ct-public public_a

# paper profile: no collect-timeout cutoff
PYTHONHASHSEED=0 \
./candidate_1_insecure.dir/candidate_1_insecure.abduce-run.bash \
  --paper-mode \
  --with-inequalities \
  --policy-report candidate_1_insecure.paper.report.json
```

Alternative (without changing CLI args): set env flag to inject paper mode from the runner.

```bash
ABDUCE_PAPER_MODE=1 \
./candidate_1_insecure.dir/candidate_1_insecure.abduce-run.bash \
  --with-inequalities \
  --policy-report candidate_1_insecure.paper.report.json
```
