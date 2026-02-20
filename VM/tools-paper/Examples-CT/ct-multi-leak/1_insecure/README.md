## CHECKCT

```bash
cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples-CT/ct-multi-leak/1_insecure

c2bc -i candidate_2_insecure.c --ct --ct-secret secret_k --ct-public public_x

binsec -sse -checkct \
  -sse-script candidate_2_insecure.dir/candidate_2_insecure.binsec.sse \
  candidate_2_insecure.dir/candidate_2_insecure.bin
```

Expected status: `insecure` (with multiple leaks).

## pyabduce (CT mode)

```bash
cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples-CT/ct-multi-leak/1_insecure

c2bc -i candidate_2_insecure.c --ct --ct-secret secret_k --ct-public public_x

./candidate_2_insecure.dir/candidate_2_insecure.abduce-run.bash \
  --with-inequalities 

./candidate_2_insecure.dir/candidate_2_insecure.abduce-run.bash \
  --with-inequalities \
  --collect-until-timeout \
  --solver-timeout 15 \
  --policy-report candidate_2_insecure.collect.report.json

./candidate_2_insecure.dir/candidate_2_insecure.abduce-run.bash   --with-inequalities   --without-disequalities   --selection-mode branch-first   --collect-until-timeout   --solver-timeout 60   --policy-report candidate_2_insecure.collect.report.json
```

For reproducible paper runs:

```bash
PYTHONHASHSEED=0 \
./candidate_2_insecure.dir/candidate_2_insecure.abduce-run.bash \
  --paper-mode \
  --with-inequalities \
  --selection-mode branch-first \
  --policy-report candidate_2_insecure.paper.report.json
```
