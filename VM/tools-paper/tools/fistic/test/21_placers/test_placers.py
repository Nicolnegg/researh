# -------------------------------------
import os
import pulseutils.logging
import pytest
from fistic import FisticOptions
from fistic.placers import *
from fistic.placers.core import GenericPlacer
from fistic.faulters import NoFault
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
def create_setup(placerclass, binary, addresses, functions, fc, sc, dfd):
    opts = FisticOptions(binary=binary, textaddr=0x10000, addresses=addresses, functions=functions,
                         fault_count=fc, skip_count=sc, dont_fault_data=dfd)
    return placerclass(opts, Logger)
# -------------------------------------
def nowhere_placer(binary, addresses, functions, fc, sc, dfd):
    placer = create_setup(NowherePlacer, binary, addresses, functions, fc, sc, dfd)
    assert list(placer.generate_targets()) == []
# -------------------------------------
def ensure_single(pclass, binary, addresses, functions, daddresses=None):
    placer = create_setup(pclass, binary, addresses, functions, 1, 1, daddresses is not None)
    assert list(placer.generate_targets()) == [ (addr,) for addr in (addresses if daddresses is None else daddresses) ]
# -------------------------------------
for tid, binary, addresses, functions in zip(('bex1', 'bex2'), ('ExampleBinary1', 'ExampleBinary2'), ('ExampleBinary1CoreAddrs', 'ExampleBinary2Addrs'), ('ExampleBinary1Funcs', 'ExampleBinary2Funcs')):
    for fc in (1,2,3):
        for sc in (1,2,3):
            for dfd in (True, False):
                exec(f'test_nowhereplacer_{tid}_{fc}{sc}{dfd} = lambda : nowhere_placer({binary}, {addresses}, {functions}, {fc}, {sc}, {dfd})')
# -------------------------------------
for tid, binary, addresses, daddrs, functions in zip(('bex1', 'bex2'),
                                                     ('ExampleBinary1', 'ExampleBinary2'),
                                                     ('ExampleBinary1CoreAddrs + ExampleBinary1DataAddrs', 'ExampleBinary2Addrs'),
                                                     ('ExampleBinary1CoreAddrs', 'ExampleBinary2Addrs'),
                                                     ('ExampleBinary1Funcs', 'ExampleBinary2Funcs')):
    exec(f'test_addresses_single_fault_{tid} = lambda : ensure_single(AddressesPlacer, {binary}, {addresses}, {functions})')
    exec(f'test_functions_single_fault_{tid} = lambda : ensure_single(FunctionsPlacer, {binary}, {addresses}, {functions})')
    exec(f'test_functions_single_fault_nodata_{tid} = lambda : ensure_single(FunctionsPlacer, {binary}, {addresses}, {functions}, {daddrs})')
# -------------------------------------
