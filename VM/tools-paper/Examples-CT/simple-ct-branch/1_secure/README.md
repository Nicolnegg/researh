# 1_secure

This folder contains the secure CT candidate:

- `candidate_1_secure.c`: branchless masking version.

## CHECKCT

```bash
cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples-CT/simple-ct-branch/1_secure
c2bc -i candidate_1_secure.c --ct --ct-secret secret_b --ct-public public_a
binsec -sse -checkct -sse-script candidate_1_secure.dir/candidate_1_secure.binsec.sse \
  candidate_1_secure.dir/candidate_1_secure.bin
```

Expected status: `secure`.

## pyabduce

```bash
cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples-CT/simple-ct-branch/1_secure
c2bc -i candidate_1_secure.c --ct --ct-secret secret_b --ct-public public_a
./candidate_1_secure.dir/candidate_1_secure.abduce-run.bash \
  --max-depth 1 --no-constant-detection --vexamples-init-count 0
```

Expected pyabduce result:

- solution is `set()`
- NAS condition is `set()`
