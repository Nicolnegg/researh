# -------------------------------------
import os
import pulseutils.logging
import pytest
from fistic import FisticOptions
from fistic.placers import AddressesPlacer
from fistic.faulters import InstructionSkipper
from fistic.evaluators import *
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
ExampleBinary1MainAddrs = [
    0x2a4, 0x2a6, 0x2a8, 0x2aa, 0x2ae,
    0x2b2, 0x2b4, 0x2b6, 0x2b8, 0x2ba, 0x2bc,
    0x2c0, 0x2c2, 0x2c4, 0x2c8, 0x2ca, 0x2cc, 0x2ce,
    0x2d0, 0x2d2
]
ExampleBinary1MainDataAddrs = [
    0x2d4, 0x2d8
]
ExampleBinary1Funcs = [ 'verifyPIN_A' ]
ExampleBinary1Main = [ 'main' ]
ExampleBinary1QemuValues = [
    EvaluationStatus.Timeout,
    EvaluationStatus.Valid, EvaluationStatus.Valid, EvaluationStatus.Valid,
    EvaluationStatus.Valid, EvaluationStatus.Valid, EvaluationStatus.Valid,
    EvaluationStatus.Valid, EvaluationStatus.Valid, EvaluationStatus.Valid,
    EvaluationStatus.Timeout, EvaluationStatus.Timeout,
    EvaluationStatus.Valid, EvaluationStatus.Valid, EvaluationStatus.Valid,
    EvaluationStatus.Invalid,
    EvaluationStatus.Valid, EvaluationStatus.Valid,
    EvaluationStatus.Invalid,
    EvaluationStatus.Valid, EvaluationStatus.Valid, EvaluationStatus.Valid,
    EvaluationStatus.Invalid,
    EvaluationStatus.Valid, EvaluationStatus.Valid, EvaluationStatus.Valid,
    EvaluationStatus.Valid, EvaluationStatus.Valid, EvaluationStatus.Valid,
    EvaluationStatus.Valid,
]
# -------------------------------------
ExampleBinary2 = 'examples/arm-aes-masking-simon.elf'
ExampleBinary2Addrs = [
    0xdc, 0xde,
    0xe0, 0xe2, 0xe4, 0xe6, 0xea, 0xec, 0xee,
    0xf0, 0xf2, 0xf4, 0xf8, 0xfa, 0xfe,
    0x100, 0x102
]
ExampleBinary2Funcs = [ 'access' ]
# -------------------------------------
def value_verification(binary, addresses, values, idx):
    opts = FisticOptions(binary=binary, textaddr=0x10000, addresses=[addresses[idx]])
    placer = AddressesPlacer(opts, Logger)
    faulter = InstructionSkipper(opts, Logger)
    evaluator = QemuEvaluator(opts, Logger)
    _, result = evaluator(list(placer.generate_mutants(faulter))[0])
    assert result == values[idx]
# -------------------------------------
for idx in range(len(ExampleBinary1CoreAddrs)):
    exec(f'test_qemu_eval_bex1_{ExampleBinary1CoreAddrs[idx]} = lambda : value_verification(ExampleBinary1, ExampleBinary1CoreAddrs, ExampleBinary1QemuValues, {idx})')
# -------------------------------------
# -------------------------------------
