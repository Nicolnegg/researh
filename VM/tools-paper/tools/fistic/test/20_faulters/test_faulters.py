# -------------------------------------
import os
import pulseutils.logging
import pytest
from fistic import FisticOptions
from fistic.placers import AddressesPlacer
from fistic.faulters import *
from fistic.faulters.core import GenericFaulter
from pulseutils.assembly import autogen_asmdata, ArmAsmData
# -------------------------------------
Logger = pulseutils.logging.Logger(4, False, False)
# -------------------------------------
ExampleBinary1 = 'examples/armv7-fissc-vp0-O2.elf'
ExampleBinary1CoreAddrs = [
    0x1d0, 0x1d2, 0x1d4, 0x1d8, 0x1dc, 0x1de,
    0x1e0, 0x1e4, 0x1e6, 0x1e8, 0x1ea, 0x1ec,
    0x1f0, 0x1f4, 0x1f6, 0x1f8, 0x1fa, 0x1fc, 0x1fe,
    0x200, 0x202, 0x204, 0x206, 0x208, 0x20a, 0x20c, 0x20e,
    0x212, 0x214, 0x216,
]
ExampleBinary1DataAddrs = [
    0x218, 0x21c, 0x220, 0x224, 0x228
]
ExampleBinary1Addrs = ExampleBinary1CoreAddrs + ExampleBinary1DataAddrs
# -------------------------------------
ExampleBinary2 = 'examples/arm-aes-masking-simon.elf'
ExampleBinary2Addrs = [
    0xdc, 0xde,
    0xe0, 0xe2, 0xe4, 0xe6, 0xea, 0xec, 0xee,
    0xf0, 0xf2, 0xf4, 0xf8, 0xfa, 0xfe,
    0x100, 0x102
]
# -------------------------------------
BFMasks = {
    2: bytearray([0xff, 0xbb]),
    4: bytearray([0x0a, 0x0c, 0x00, 0x09]),
}
# -------------------------------------
def mutant_cleanup(mutant):
    os.remove(mutant.binary)
# -------------------------------------
def create_setup(faulterclass, addrlist, binary, idx):
    maddrs = [ addrlist[idx] ]
    naddrs = [ a for a in addrlist if a != maddrs[0] ]
    opts = FisticOptions(binary=binary, textaddr=0x10000, addresses=maddrs, masks=BFMasks)
    placer = AddressesPlacer(opts, Logger)
    faulter = faulterclass(opts, Logger)
    target = list(placer.generate_mutants(faulter))[0]
    asm_src = autogen_asmdata(binary, ArmAsmData, 'arm-none-eabi-objdump')
    asm_tgt = autogen_asmdata(target.binary, ArmAsmData, 'arm-none-eabi-objdump')
    return asm_src, asm_tgt
# -------------------------------------
NopInstructions = ('nop', 'nop.w', 'nopne')
InstructionAliases = (
    { 'movs', 'movne' },
    { 'cmp', 'cmpne' },
    { 'ldrb.w', 'ldrbge.w' },
    { 'bl', 'blcc' },
    { 'ldr', 'ldrpl' },
)
# -------------------------------------
def are_aliases(i1, i2):
    return i1 == i2 or set((i1, i2)) in InstructionAliases
# -------------------------------------
def any_pr(faulterclass, addrlist, binary, idx):
    asm_src, asm_tgt = create_setup(faulterclass, addrlist, binary, idx)
    for addr in [ a for a in addrlist if a != addrlist[idx] ]:
        src_ba = asm_src.get_instruction_bytes(addr)
        try:
            tgt_ba = asm_tgt.get_instruction_bytes(addr)
        except KeyError as e:
            pytest.skip(f'mutation @{e} broke instruction map')
        assert src_ba == tgt_ba
# -------------------------------------
def nf_do(addrlist, binary, idx):
    asm_src, asm_tgt = create_setup(NoFault, addrlist, binary, idx)
    src_ba = asm_src.get_instruction_bytes(addrlist[idx])
    tgt_ba = asm_tgt.get_instruction_bytes(addrlist[idx])
    assert src_ba == tgt_ba
# -------------------------------------
def sk_do(addrlist, binary, idx):
    asm_src, asm_tgt = create_setup(InstructionSkipper, addrlist, binary, idx)
    src_ra, src_rb = asm_src.get_instruction(addrlist[idx])
    tgt_ra, tgt_rb = asm_tgt.get_instruction(addrlist[idx])
    assert src_ra in NopInstructions or src_ra != tgt_ra
    assert src_ra in NopInstructions or src_rb != tgt_rb
    assert tgt_ra in NopInstructions
# -------------------------------------
class RandomMatchCounter:

    def __init__(self, tolerance=1):
        self.tolerance = tolerance
        self.value = 0

    def __iadd__(self, other):
        self.value += other
        return self

    def __le__(self, other):
        return self.value <= other

    def __bool__(self):
        return self.value <= self.tolerance
# -------------------------------------
def rpi_do(addrlist, binary, idx, statcpt):
    asm_src, asm_tgt = create_setup(RandomPayloadInjection, addrlist, binary, idx)
    src_ra, src_rb = asm_src.get_instruction(addrlist[idx])
    tgt_ra, tgt_rb = asm_tgt.get_instruction(addrlist[idx])
    statcpt += src_ra == tgt_ra and src_rb == tgt_rb
    assert statcpt
# -------------------------------------
def xorba(lo, ro):
    return bytearray([_l ^_r for _l, _r in zip(lo, ro)])
# -------------------------------------
def bf_do(addrlist, binary, idx):
    asm_src, asm_tgt = create_setup(BitflipFaulter, addrlist, binary, idx)
    src_ic = asm_src.get_instruction_bytes(addrlist[idx])
    tgt_ic = asm_tgt.get_instruction_bytes(addrlist[idx])
    assert ((len(src_ic) <= len(tgt_ic) and tgt_ic[:len(src_ic)] == xorba(src_ic, BFMasks[asm_src.get_instruction_size(addrlist[idx])]))
         or (len(src_ic) > len(tgt_ic) and tgt_ic == xorba(src_ic, BFMasks[asm_src.get_instruction_size(addrlist[idx])])[:len(tgt_ic)]))
# -------------------------------------
for idx in range(len(ExampleBinary1CoreAddrs)):
    exec(f'test_skipper_binary1_{idx}_fault = lambda : sk_do(ExampleBinary1CoreAddrs, ExampleBinary1, {idx})')
    exec(f'test_skipper_binary1_{idx}_preserve = lambda: any_pr(InstructionSkipper, ExampleBinary1CoreAddrs, ExampleBinary1, {idx})')
for idx in range(len(ExampleBinary2Addrs)):
    exec(f'test_skipper_binary2_{idx}_fault = lambda : sk_do(ExampleBinary2Addrs, ExampleBinary2, {idx})')
    exec(f'test_skipper_binary2_{idx}_preserve = lambda: any_pr(InstructionSkipper, ExampleBinary2Addrs, ExampleBinary2, {idx})')
# -------------------------------------
rmc = RandomMatchCounter()
# -------------------------------------
for idx in range(len(ExampleBinary1CoreAddrs)):
    exec(f'test_rpi_binary1_{idx}_fault = lambda : rpi_do(ExampleBinary1CoreAddrs, ExampleBinary1, {idx}, rmc)')
    exec(f'test_rpi_binary1_{idx}_preserve = lambda: any_pr(RandomPayloadInjection, ExampleBinary1CoreAddrs, ExampleBinary1, {idx})')
for idx in range(len(ExampleBinary2Addrs)):
    exec(f'test_rpi_binary2_{idx}_fault = lambda : rpi_do(ExampleBinary2Addrs, ExampleBinary2, {idx}, rmc)')
    exec(f'test_rpi_binary2_{idx}_preserve = lambda: any_pr(RandomPayloadInjection, ExampleBinary2Addrs, ExampleBinary2, {idx})')
# -------------------------------------
for idx in range(len(ExampleBinary1CoreAddrs)):
    exec(f'test_bf_binary1_{idx}_fault = lambda : bf_do(ExampleBinary1CoreAddrs, ExampleBinary1, {idx})')
    exec(f'test_bf_binary1_{idx}_preserve = lambda: any_pr(BitflipFaulter, ExampleBinary1CoreAddrs, ExampleBinary1, {idx})')
for idx in range(len(ExampleBinary2Addrs)):
    exec(f'test_bf_binary2_{idx}_fault = lambda : bf_do(ExampleBinary2Addrs, ExampleBinary2, {idx})')
    exec(f'test_bf_binary2_{idx}_preserve = lambda: any_pr(BitflipFaulter, ExampleBinary2Addrs, ExampleBinary2, {idx})')
# -------------------------------------
for idx in range(len(ExampleBinary1CoreAddrs)):
    exec(f'test_nf_binary1_{idx}_fault = lambda : nf_do(ExampleBinary1CoreAddrs, ExampleBinary1, {idx})')
    exec(f'test_nf_binary1_{idx}_preserve = lambda: any_pr(NoFault, ExampleBinary1CoreAddrs, ExampleBinary1, {idx})')
for idx in range(len(ExampleBinary2Addrs)):
    exec(f'test_nf_binary2_{idx}_fault = lambda : nf_do(ExampleBinary2Addrs, ExampleBinary2, {idx})')
    exec(f'test_nf_binary2_{idx}_preserve = lambda: any_pr(NoFault, ExampleBinary2Addrs, ExampleBinary2, {idx})')
# -------------------------------------
def test_generic_faulter_nocall():
    gf = GenericFaulter(None, None)
    try:
        gf(None, None)
    except NotImplementedError:
        return
    pytest.fail('Generic faulter did not raise error on call')
# -------------------------------------
