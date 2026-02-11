# -------------------------------------
from importlib.util import spec_from_loader, module_from_spec
from importlib.machinery import SourceFileLoader
clispec = spec_from_loader('fistic_core', SourceFileLoader('fistic_core', 'fistic-core'))
fistic_core = module_from_spec(clispec)
clispec.loader.exec_module(fistic_core)
ap = fistic_core.ap
main = fistic_core.main
# ----------------------------------------
def test_functional_msimple():
    main(ap.parse_args('-b examples/armv7-fissc-vp0-O2.elf -e none --fault-model skip -n 1 -t 10000 --faulted-binaries-dir .fistic --function verifyPIN_A'.split()))
    main(ap.parse_args('-b examples/arm-aes-masking-simon.elf -e none --fault-model skip -n 1 -t 10000 --faulted-binaries-dir .fistic --function access'.split()))
# -------------------------------------
def test_functional_mutate2():
    main(ap.parse_args('-b examples/armv7-fissc-vp0-O2.elf -e none --fault-model skip -n 2 -t 10000 --faulted-binaries-dir .fistic --function verifyPIN_A'.split()))
    main(ap.parse_args('-b examples/arm-aes-masking-simon.elf -e none --fault-model skip -n 2 -t 10000 --faulted-binaries-dir .fistic --function access'.split()))
# -------------------------------------
def test_functional_qemu1():
    main(ap.parse_args('-b examples/armv7-fissc-vp0-O2.elf -e qemu --fault-model skip -n 1 -t 10000 --faulted-binaries-dir .fistic --function verifyPIN_A'.split()))
    main(ap.parse_args('-b examples/arm-aes-masking-simon.elf -e qemu --fault-model skip -n 1 -t 10000 --faulted-binaries-dir .fistic --function access'.split()))
# -------------------------------------
def test_functional_qemu2():
#    main(ap.parse_args('-b examples/armv7-fissc-vp0-O2.elf -e qemu --fault-model skip -n 2 -t 10000 --faulted-binaries-dir .fistic --function verifyPIN_A'.split()))
    main(ap.parse_args('-b examples/arm-aes-masking-simon.elf -e qemu --fault-model skip -n 2 -t 10000 --faulted-binaries-dir .fistic --function access'.split()))
# -------------------------------------
def test_functional_qemup():
    main(ap.parse_args('-b examples/armv7-fissc-vp0-O2.elf -e qemu --fault-model skip -n 1 -t 10000 --faulted-binaries-dir .fistic --function verifyPIN_A --parallel'.split()))
    main(ap.parse_args('-b examples/arm-aes-masking-simon.elf -e qemu --fault-model skip -n 1 -t 10000 --faulted-binaries-dir .fistic --function access --parallel'.split()))
# -------------------------------------
def test_functional_qemup2():
    main(ap.parse_args('-b examples/armv7-fissc-vp0-O2.elf -e qemu --fault-model skip -n 2 -t 10000 --faulted-binaries-dir .fistic --function verifyPIN_A --parallel'.split()))
    main(ap.parse_args('-b examples/arm-aes-masking-simon.elf -e qemu --fault-model skip -n 2 -t 10000 --faulted-binaries-dir .fistic --function access --parallel'.split()))
# -------------------------------------
