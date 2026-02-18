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
```

Expected CHECKCT summary:

- `candidate_1_insecure`: `Program status is : insecure`
- `candidate_1_secure`: `Program status is : secure`

## Run with pyabduce (CT mode)

The generated `*.abduce-run.bash` already forwards `--ct-mode` automatically when built with `c2bc --ct`.

```bash
# insecure case
cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples-CT/simple-ct-branch/1_insecure
c2bc -i candidate_1_insecure.c --ct --ct-secret secret_b --ct-public public_a
./candidate_1_insecure.dir/candidate_1_insecure.abduce-run.bash \
  --max-depth 1 --no-constant-detection --vexamples-init-count 0

# secure case
cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples-CT/simple-ct-branch/1_secure
c2bc -i candidate_1_secure.c --ct --ct-secret secret_b --ct-public public_a
./candidate_1_secure.dir/candidate_1_secure.abduce-run.bash \
  --max-depth 1 --no-constant-detection --vexamples-init-count 0
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
