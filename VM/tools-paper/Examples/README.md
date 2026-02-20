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

cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples/example-empty-default
c2bc -i example.c
./example.dir/example.abduce-run.bash --with-inequalities
# expected: selected constraint (necessary & sufficient): {true}

cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples/'example-minus-a<b'
c2bc -i example.c
./example.dir/example.abduce-run.bash --with-inequalities

cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples/'example-plus-a>b'
c2bc -i example.c
./example.dir/example.abduce-run.bash --with-inequalities

cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples/example-chain-if-error
c2bc -i example.c
./example.dir/example.abduce-run.bash --with-inequalities

cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples/sse-mock-example
c2bc -i example.c
./example.dir/example.abduce-run.bash --with-inequalities

```

Look value a and b

```bash
objdump -t example.dir/example.bin | egrep '<addr>|<addr>|nondet_slot'
```
