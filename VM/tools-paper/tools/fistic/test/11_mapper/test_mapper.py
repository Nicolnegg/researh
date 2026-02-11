# -------------------------------------
import os
import pulseutils.logging
import pytest
from fistic import Mapper, MapperFromMap
# -------------------------------------
Logger = pulseutils.logging.Logger(4, False, False)
# -------------------------------------
ExampleBinary1 = 'examples/armv7-fissc-vp0-O2.elf'
# -------------------------------------
ExampleBinary2 = 'examples/arm-aes-masking-simon.elf'
# -------------------------------------
OutputYml = 'fistic.yml'
# -------------------------------------
def mapper_build(binary):
    mapper = Mapper(binary, Logger, mode='pulseutils')
    mapper.parse()
    assert mapper.parsed
    assert len(mapper.mapping) > 0
# -------------------------------------
def mapper_dump_load(binary):
    mapperd = Mapper(binary, Logger, mode='pulseutils')
    with open(OutputYml, 'w') as stream:
        mapperd.write_config(stream)
    mapperl = MapperFromMap(binary, Logger, OutputYml)
    mapperl.parse()
    assert mapperd.mapping == mapperl.mapping
# -------------------------------------
for bid, binary in zip(('bex1', 'bex2'), ('ExampleBinary1', 'ExampleBinary2')):
    exec(f'test_mapper_build_{bid} = lambda : mapper_build({binary})')
    exec(f'test_mapper_dump_load_{bid} = lambda : mapper_dump_load({binary})')
# -------------------------------------
