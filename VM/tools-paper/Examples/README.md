# Run All Examples

This guide runs all examples in `VM/tools-paper/Examples` using the same workflow:
`c2bc -i example.c` -> `./example.dir/example.abduce-run.bash`

## 1. Environment setup (run once)

```bash
cd ~/Documentos/M2-Cyber/RESEARCH
eval $(opam env)

c2bc -i example.c
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
./example.dir/example.abduce-run.bash --with-inequalities
-> overflow

cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples/'example-empty-default'
c2bc -i example.c
./example.dir/example.abduce-run.bash --with-inequalities


cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples/'example-minus-a<b'
c2bc -i example.c
./example.dir/example.abduce-run.bash --with-inequalities

cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples/'example-plus-a>b'
c2bc -i example.c
./example.dir/example.abduce-run.bash --with-inequalities

cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples/sse-mock-example
c2bc -i example.c
./example.dir/example.abduce-run.bash --with-inequalities

cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples/example-add-a-b-gt-100
c2bc -i example.c
./example.dir/example.abduce-run.bash --with-inequalities

cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples/example-sub-a-b-gt-100
c2bc -i example.c
./example.dir/example.abduce-run.bash --with-inequalities

cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples/example-mul-a-b-gt-100
c2bc -i example.c
./example.dir/example.abduce-run.bash --with-inequalities --with-mul-terms 

cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples/example-bitand-mask
c2bc -i example.c
./example.dir/example.abduce-run.bash  --with-bitwise-terms 

cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples/example-bitor-mask
c2bc -i example.c
./example.dir/example.abduce-run.bash --with-bitwise-terms 

cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples/example-bitnot-mask
c2bc -i example.c
./example.dir/example.abduce-run.bash --with-bitwise-terms 

cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples/example-shr-a-lt
c2bc -i example.c
./example.dir/example.abduce-run.bash --with-inequalities --with-bitwise-terms 

cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples/example-shl-a-lt-5u
c2bc -i example.c
./example.dir/example.abduce-run.bash --with-inequalities --with-bitwise-terms --with-shift-terms --binsec-delete-configs

cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples/example-shl-a-ge
c2bc -i example.c
./example.dir/example.abduce-run.bash --with-inequalities --with-bitwise-terms 

# keep temp BINSEC scripts only for debugging
# ./example.dir/example.abduce-run.bash ... --keep-binsec-configs

cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples/example-chain-mixed-arith-if
c2bc -i example.c
./example.dir/example.abduce-run.bash --with-inequalities --with-mul-terms

cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples/example-long-if-condition
c2bc -i example.c
./example.dir/example.abduce-run.bash --with-inequalities

cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples/example-chain-if-error
c2bc -i example.c
./example.dir/example.abduce-run.bash --with-inequalities 


cd ~/Documentos/M2-Cyber/RESEARCH/VM/tools-paper/Examples/example-chain-all-ops
c2bc -i example.c
./example.dir/example.abduce-run.bash   --with-inequalities --with-bitwise-terms --with-shift-terms   --bitwise-term-limit 4 --max-depth 2   --input-variables-only --without-disequalities   --max-solutions 30 --best-effort-policy   --solver-timeout 240


```

Look value a and b

```bash
objdump -t example.dir/example.bin | egrep '<addr>|<addr>|nondet_slot'

objdump -t example.dir/example.bin | grep reach
```
