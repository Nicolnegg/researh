# Examples-CT: Usage Guide (c2bc + pyabduce in Constant-Time mode)

This directory contains examples to infer constraints that turn a CHECKCT
`insecure` program into `secure`.

## 1) Environment setup

```bash
cd ~/Documentos/M2-Cyber/RESEARCH
eval $(opam env)

cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper
source venv/bin/activate
export PATH=/home/nicol/Documentos/M2-Cyber/RESEARCH/binsec/_opam/bin:$PATH
```

## 2) How to mark public and secret in c2bc

`c2bc` provides explicit CT options:

- `--ct`: enables the CHECKCT pipeline.
- `--ct-secret <sym[,sym...]>`: declares secret variables.
- `--ct-public <sym[,sym...]>`: declares public variables.

Example:

```bash
c2bc -i candidate_1_insecure.c --ct --ct-secret secret_b --ct-public public_a
```

For multiple variables:

```bash
c2bc -i prog.c --ct --ct-secret secret_k,secret_m --ct-public public_x,public_y
```

Notes:

- Names must match global symbols in the program.
- `secret` defines what must not leak via control-flow or memory access.
- `public` defines allowed observable inputs.

## 3) What c2bc generates for CT abduction

Inside `*.dir/` you will see files such as:

- `*.abduce-run.bash`: runner script to launch `pyabduce`.
- `*.abd.literals.txt`: candidate literal universe.
- `*.abd.directives.txt`: reach/cut goals for BINSEC.
- `*.binsec.sse` and temporary configs in `.binsec-config/`.

## 4) How pyabduce works in CT mode

High-level flow:

1. Evaluates baseline with CHECKCT (`secure/insecure` + leaks).
2. Generates and tests candidates (BINSEC + pre-pruning).
3. Stores sufficient solutions.
4. Checks necessity (NAS).
5. Selects main policy according to ranking mode.
6. Re-validates baseline vs selected and exports `report.json` (if requested).

## 5) Base commands

### Simple case

```bash
cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples-CT/simple-ct-branch/1_insecure

c2bc -i candidate_1_insecure.c --ct --ct-secret secret_b --ct-public public_a

./candidate_1_insecure.dir/candidate_1_insecure.abduce-run.bash \
  --with-inequalities \
  --selection-mode branch-first \
  --policy-report candidate_1_insecure.report.json
```

### Harder case (multi-leak)

```bash
cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples-CT/ct-multi-leak/1_insecure

c2bc -i candidate_2_insecure.c --ct --ct-secret secret_k --ct-public public_x

./candidate_2_insecure.dir/candidate_2_insecure.abduce-run.bash \
  --with-inequalities \
  --collect-until-timeout \
  --solver-timeout 15 \
  --selection-mode branch-first \
  --policy-report candidate_2_insecure.collect.report.json
```

## 6) Useful pyabduce options (CT)

- `--ct-mode`: uses CHECKCT contract (`secure/insecure/unknown`).
- `--with-inequalities`: enables `<s` literals (important for branch constraints).
- `--without-disequalities`: removes `<>` operator to reduce search space.
- `--collect-until-timeout`: keeps searching for more NAS until global timeout.
- `--solver-timeout <s>`: total search budget.
- `--selection-mode branch-first|size-complexity`:
  - `branch-first`: prioritizes branch-pivot policies when robustly detected.
  - `size-complexity`: prioritizes fewer literals + lower syntax complexity.
- `--policy-report <file.json>`: writes structured JSON report.
- `-d`: detailed debug logs.

## 7) How to read output

Key lines:

- `checkct status: insecure|secure`
- `checkct leak: Instruction ... has ... leak`
- `satisfying solution: {...}` (sufficient)
- `nas conditions (all): [...]` (detected necessary policies)
- `selected policy: {...}` (main policy)
- `alternative policies: [...]` (alternatives)
- `policy report written: ...json`

Semantics:

- Policies `P1`, `P2`, ... are alternatives (OR across policies).
- Inside one policy, literals are conjunctive (AND).

## 8) Recommended reproducibility settings

For stable research runs:

- fix Python hash seed:

```bash
PYTHONHASHSEED=0 ./candidate_1_insecure.dir/candidate_1_insecure.abduce-run.bash \
  --paper-mode --with-inequalities --policy-report run.paper.report.json
```

- same machine, same BINSEC/opam commit, same timeouts.

## 9) Minimal expected report.json structure

- `ct_validation.baseline.status`
- `ct_validation.selected.status`
- `selected_policy`
- `alternatives`
- `selection_mode`
- `stats`
- `run_profile`

## 10) Available examples

- `simple-ct-branch/1_insecure`
- `simple-ct-branch/1_secure`
- `ct-multi-leak/1_insecure`
