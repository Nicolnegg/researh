# -------------------------------------
def test_cli_help(script_runner):
    script_runner.run('fistic-core -h', shell=True, check=True)
    script_runner.run('fistic-mapper -h', shell=True, check=True)
# -------------------------------------
def test_cli_msimple(script_runner):
    script_runner.run('fistic-core -b examples/armv7-fissc-vp0-O2.elf -e none --fault-model skip -n 1 -t 10000 --faulted-binaries-dir .fistic --function verifyPIN_A', shell=True, check=True)
    script_runner.run('fistic-core -b examples/arm-aes-masking-simon.elf -e none --fault-model skip -n 1 -t 10000 --faulted-binaries-dir .fistic --function access', shell=True, check=True)
# -------------------------------------
def test_cli_mutate2(script_runner):
    script_runner.run('fistic-core -b examples/armv7-fissc-vp0-O2.elf -e none --fault-model skip -n 2 -t 10000 --faulted-binaries-dir .fistic --function verifyPIN_A', shell=True, check=True)
    script_runner.run('fistic-core -b examples/arm-aes-masking-simon.elf -e none --fault-model skip -n 2 -t 10000 --faulted-binaries-dir .fistic --function access', shell=True, check=True)
# -------------------------------------
def test_cli_qemu1(script_runner):
    script_runner.run('fistic-core -b examples/armv7-fissc-vp0-O2.elf -e qemu --fault-model skip -n 1 -t 10000 --faulted-binaries-dir .fistic --function verifyPIN_A', shell=True, check=True)
    script_runner.run('fistic-core -b examples/arm-aes-masking-simon.elf -e qemu --fault-model skip -n 1 -t 10000 --faulted-binaries-dir .fistic --function access', shell=True, check=True)
# -------------------------------------
def test_cli_qemu2(script_runner):
#    script_runner.run('fistic-core -b examples/armv7-fissc-vp0-O2.elf -e qemu --fault-model skip -n 2 -t 10000 --faulted-binaries-dir .fistic --function verifyPIN_A', shell=True, check=True)
    script_runner.run('fistic-core -b examples/arm-aes-masking-simon.elf -e qemu --fault-model skip -n 2 -t 10000 --faulted-binaries-dir .fistic --function access', shell=True, check=True)
# -------------------------------------
def test_cli_qemup(script_runner):
    script_runner.run('fistic-core -b examples/armv7-fissc-vp0-O2.elf -e qemu --fault-model skip -n 1 -t 10000 --faulted-binaries-dir .fistic --function verifyPIN_A --parallel', shell=True, check=True)
    script_runner.run('fistic-core -b examples/arm-aes-masking-simon.elf -e qemu --fault-model skip -n 1 -t 10000 --faulted-binaries-dir .fistic --function access --parallel', shell=True, check=True)
# -------------------------------------
def test_cli_qemup2(script_runner):
    script_runner.run('fistic-core -b examples/armv7-fissc-vp0-O2.elf -e qemu --fault-model skip -n 2 -t 10000 --faulted-binaries-dir .fistic --function verifyPIN_A --parallel', shell=True, check=True)
    script_runner.run('fistic-core -b examples/arm-aes-masking-simon.elf -e qemu --fault-model skip -n 2 -t 10000 --faulted-binaries-dir .fistic --function access --parallel', shell=True, check=True)
# -------------------------------------
def test_cli_communicate(script_runner):
    next_str = 'next\n' * 50
    script_runner.run(f'echo -e "{next_str}" | fistic-core -b examples/armv7-fissc-vp0-O2.elf -e qemu --fault-model skip -n 1 -t 10000 --faulted-binaries-dir .fistic --function verifyPIN_A --communicate', shell=True, check=True)
    script_runner.run(f'echo -e "{next_str}" | fistic-core -b examples/arm-aes-masking-simon.elf -e qemu --fault-model skip -n 1 -t 10000 --faulted-binaries-dir .fistic --function access --communicate', shell=True, check=True)
# -------------------------------------
def test_cli_mapper(script_runner):
    script_runner.run('fistic-mapper -b examples/armv7-fissc-vp0-O2.elf', shell=True, check=True)
    script_runner.run('fistic-mapper -b examples/arm-aes-masking-simon.elf', shell=True, check=True)
# -------------------------------------
