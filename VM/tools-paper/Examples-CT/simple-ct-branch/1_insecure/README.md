# 1_insecure

This folder contains the insecure CT candidate:

- `candidate_1_insecure.c`: branch depends on `secret_b` (`if (secret_b > 0)`).

## CHECKCT

```bash
cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples-CT/simple-ct-branch/1_insecure
c2bc -i candidate_1_insecure.c --ct --ct-secret secret_b --ct-public public_a
binsec -sse -checkct -sse-script candidate_1_insecure.dir/candidate_1_insecure.binsec.sse \
  candidate_1_insecure.dir/candidate_1_insecure.bin
```

Expected status: `insecure`.

## pyabduce

```bash
cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples-CT/simple-ct-branch/1_insecure
c2bc -i candidate_1_insecure.c --ct --ct-secret secret_b --ct-public public_a
./candidate_1_insecure.dir/candidate_1_insecure.abduce-run.bash --with-inequalities

./candidate_1_insecure.dir/candidate_1_insecure.abduce-run.bash \
  --with-inequalities \
  --collect-until-timeout \
  --solver-timeout 10 \
  --policy-report candidate_1_insecure.collect.report.json -> more candidate

  ./candidate_1_insecure.dir/candidate_1_insecure.abduce-run.bash --with-inequalities --selection-mode size-complexity --policy-report candidate_1_insecure.report.json

```

Expected pyabduce logs:

- `checkct status: insecure`
- `checkct leak: Instruction ... has ... leak`
