# Run All Examples

This guide runs all examples in `VM/tools-paper/Examples` using the same workflow:
`c2bc -i example.c` -> `./example.dir/example.abduce-run.bash`

## 1. Environment setup (run once)

```bash
cd ~/Documentos/M2-Cyber/RESEARCH
eval $(opam env)

cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper
source venv/bin/activate
export PATH=/home/nicol/Documentos/M2-Cyber/RESEARCH/binsec/_opam/bin:$PATH
```

## 2. Run each example manually

```bash
cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples/simple-example
c2bc -i example.c
./example.dir/example.abduce-run.bash 

cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples/'example-ineq-a>=b'
c2bc -i example.c
./example.dir/example.abduce-run.bash --with-inequalities

cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples/'example-ineq-a>a+1'
c2bc -i example.c
timeout 20s ./example.dir/example.abduce-run.bash --with-inequalities
->error imposible
->voir

->intentar cadenas de if a>b :
if b>c:
error

cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples/'example-minus-a<b'
c2bc -i example.c
./example.dir/example.abduce-run.bash --with-inequalities

cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples/'example-plus-a>b'
c2bc -i example.c
./example.dir/example.abduce-run.bash --with-inequalities

cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples/sse-mock-example
c2bc -i example.c
./example.dir/example.abduce-run.bash --with-inequalities

```

## 3. Run all examples automatically

```bash
cd ~/Documentos/M2-Cyber/RESEARCH

eval $(opam env)

cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper
source venv/bin/activate
export PATH=/home/nicol/Documentos/M2-Cyber/RESEARCH/binsec/_opam/bin:$PATH

ROOT=~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples
EXAMPLES=(
  "simple-example"
  "example-ineq-a>=b"
  "example-ineq-a>a+1"
  "example-minus-a<b"
  "example-plus-a>b"
  "sse-mock-example"
)

for ex in "${EXAMPLES[@]}"; do
  echo "== Running $ex =="
  cd "$ROOT/$ex"
  c2bc -i example.c
  ./example.dir/example.abduce-run.bash --with-inequalities --max-depth 3
  echo
  cd "$ROOT"
done
```

## Notes

- Folder names containing `>` or `<` must be run with --with-inequalities.
- If you want stronger search for inequalities, you can pass extra flags, for example:
  `./example.dir/example.abduce-run.bash --with-inequalities --max-depth 2`

## Examples-CT

Constant-time examples are now available in:

- `VM/tools-paper/Examples-CT`

Quick start:

```bash
cd ~/Documentos/M2-Cyber/RESEARCH
eval $(opam env)

cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper
source venv/bin/activate
export PATH=/home/nicol/Documentos/M2-Cyber/RESEARCH/binsec/_opam/bin:$PATH

cd Examples-CT/simple-ct-branch
./run_checkct.sh
```
