# Examples-CT

Guia unica para probar ejemplos CT con `c2bc + pyabduce`.

## 1) Preparar entorno

```bash
cd ~/Documentos/M2-Cyber/RESEARCH

eval $(opam env)
cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper
source venv/bin/activate

export PATH=/home/nicol/Documentos/M2-Cyber/RESEARCH/binsec/_opam/bin:$PATH
```

## 2) Como correr un ejemplo (manual)


```bash
cd <carpeta-del-ejemplo>

c2bc -i <archivo.c> --ct --ct-secret <secret> --ct-public <public>

./<archivo>.dir/<archivo>.abduce-run.bash \
  --with-inequalities \
  --policy-report <archivo>.report.json
```

Opcionales ya existentes:
- `--with-bitwise-terms`
- `--with-mul-terms`
- `--solver-timeout <segundos>`

## 3) Ejemplos disponibles

### simple-ct-branch (insecure)

```bash
cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples-CT/simple-ct-branch/1_insecure
c2bc -i candidate_1_insecure.c --ct --ct-secret secret_b --ct-public public_a
./candidate_1_insecure.dir/candidate_1_insecure.abduce-run.bash --with-inequalities --policy-report candidate_1_insecure.report.json
```

### simple-ct-branch (secure)

```bash
cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples-CT/simple-ct-branch/1_secure
c2bc -i candidate_1_secure.c --ct --ct-secret secret_b --ct-public public_a
./candidate_1_secure.dir/candidate_1_secure.abduce-run.bash --with-inequalities --policy-report candidate_1_secure.report.json
```

### ct-range-policy

```bash
cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples-CT/ct-range-policy/1_insecure
c2bc -i candidate_3_insecure.c --ct --ct-secret secret_k --ct-public public_x
./candidate_3_insecure.dir/candidate_3_insecure.abduce-run.bash --with-inequalities --policy-report candidate_3_insecure.report.json
```

### ct-asym-policy

```bash
cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples-CT/ct-asym-policy/1_insecure
c2bc -i candidate_4_insecure.c --ct --ct-secret secret_k --ct-public public_x
./candidate_4_insecure.dir/candidate_4_insecure.abduce-run.bash --with-inequalities --policy-report candidate_4_insecure.report.json
```

### ct-easy-pass

```bash
cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples-CT/ct-easy-pass/1_insecure
c2bc -i candidate_5_insecure.c --ct --ct-secret secret_b --ct-public public_x
./candidate_5_insecure.dir/candidate_5_insecure.abduce-run.bash --with-inequalities --policy-report candidate_5_insecure.report.json
```

### ct-or-multi-branch

```bash
cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples-CT/ct-or-multi-branch/1_insecure
c2bc -i candidate_6_insecure.c --ct --ct-secret secret_k --ct-public public_x
./candidate_6_insecure.dir/candidate_6_insecure.abduce-run.bash --with-inequalities --policy-report candidate_6_insecure.report.json
```

### ct-shift-window

```bash
cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples-CT/ct-shift-window/1_insecure
c2bc -i candidate_7_insecure.c --ct --ct-secret secret_k --ct-public public_x
./candidate_7_insecure.dir/candidate_7_insecure.abduce-run.bash --with-inequalities --policy-report candidate_7_insecure.report.json
```

### ct-and-window

```bash
cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples-CT/ct-and-window/1_insecure
c2bc -i candidate_8_insecure.c --ct --ct-secret secret_k --ct-public public_x
./candidate_8_insecure.dir/candidate_8_insecure.abduce-run.bash --with-inequalities --with-bitwise-terms --max-depth 2 --solver-timeout 90 --policy-report candidate_8_insecure.report.json
```

## 4) Que revisar en salida

- `checkct status: insecure|secure`
- `selected policy: ...`
- `ct_validation.baseline.status`
- `ct_validation.selected.status`
- `policy report written: ...json`
