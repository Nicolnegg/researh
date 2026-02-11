'''Fistic Mapper utilities for generating binary instruction maps'''
# --------------------
import sys
import io
import enum
import subprocess
from subprocess import Popen
import yaml
try:
    from yaml import CLoader as ymlLoader, CDumper as ymlDumper
except ImportError:
    from yaml import Loader as ymlLoader, Dumper as ymlDumper
from pulseutils.assembly import ArmAsmData, autogen_asmdata
# --------------------
class IType(enum.Enum):
    '''Armv7 Instruction Type

    :param INSN: Instruction
    :param DATA: Inlined data literal
    '''
    INSN = 1
    DATA = 2
# --------------------
# --------------------
class Bundler:
    '''Instruction bundler.

    Bundles a parsed instruction for easier reuse.

    :param addr: instruction address
    :param itype: arm insturction type
    :param size: instruction size (in bytes)
    :type addr: int
    :type itype: :class:`IType`
    :type size: int
   '''

    def __init__(self, addr=0, itype=IType.INSN, size=0):
        '''Bundle constructor
        '''
        self.addr = addr
        self.itype = itype
        self.size = size

    def is_inst(self):
        '''Check if the bundled instruction is an arm instruction.

        :return: True iff the bundled instruction is an arm instruction
        :rtype: bool
        '''
        return self.itype == IType.INSN

    def is_data(self):
        '''Check if the bundled instruction is an arm data literal.

        :return: True iff the bundled instruction is an arm data literal.
        :rtype: bool
        '''
        return self.itype == IType.DATA

    def __repr__(self):
        return f"({self.addr},{self.itype},{self.size})"

    def __eq__(self, other):
        return self.addr == other.addr and self.itype == other.itype and self.size == other.size
# --------------------
class MapperCore:
    '''Generic binary instruction mapper.

    Main class for generating the instruction map of a target binary.

    :param binary: target binary file
    :param logger: logging utility
    :param parsed: flag for completed mapping generation
    :param mapping: instructions mapping, by symbol, by address, valid if **parsed** is True
    :type binary: str
    :type parsed: bool
    :type mapping: dict(str, dict(int, :class:`Bundler`))
    '''

    def __init__(self, binary, logger):
        self.binary = binary
        self.logger = logger
        self.parsed = False
        self.mapping = {}

    def __getitem__(self, k):
        if not self.parsed:
            self.parse()
        return self.mapping[k]

    def parse(self):
        '''Parse the binary and generate the mapping.

        :return: None
        '''
        raise NotImplementedError(self)

    def get_size(self, addr):
        '''Get the size (in bytes) of the instruction.

        :param addr: address of the instruction
        :type addr: int
        :return: the size in bytes of the instruction at address :code:`addr`
        :rtype: int
        '''
        if not self.parsed:
            self.parse()
        for _, rdata in self.mapping.items():
            if addr in rdata:
                return rdata[addr].size
        raise KeyError(addr)

    def write_config(self, target):
        '''Generate a forwardable mapping yaml file.

        :param target: stream to write the mapping to
        :type target: fp('w')
        '''
        if not self.parsed:
            self.parse()
        yaml.dump(self.mapping, target, Dumper=ymlDumper)
# --------------------
class MapperFromMap(MapperCore):
    '''Utility class for building a mapper from a map file.

    Builds a :code:`fistic.mapper.MapperCore` instance from a map file.
    This is the converse of saving maps with the :code:`write_config` method.

    :param mapfile: file containing a yaml map
    :type mapfile: str
    '''

    def __init__(self, binary, logger, mapfile):
        super().__init__(binary, logger)
        self.mapfile = mapfile

    def parse(self):
        with open(self.mapfile) as stream:
            self.mapping = yaml.load(stream, Loader=ymlLoader)
        self.parsed = True
# --------------------
class LegacyMapper(MapperCore):
    '''Legacy fistic instruction mapper.

    .. deprecated:: 0.3.0
       use :class:`fistic.mapper.PulseUtilsMapper` instead

    .. warning::

       the class remains for legacy code usage purposes, it is known to crash on non-digitally aligned functions.
    '''

    def __init__(self, binary, logger):
        super().__init__(binary, logger)
        self.routine = None
        self.addrs = {}
        self.last_bundler = None

    def new_routine(self, name):
        if self.routine is not None:
            if self.routine in self.mapping:
                self.logger.warning(f'multiple disassembly of routine {self.routine}; keeping last')
            self.mapping[self.routine] = self.addrs
        self.routine = name
        self.addrs = {}

    def get_objdump_log(self):
        proc = Popen(['arm-none-eabi-objdump', '--disassemble', self.binary], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        cout, _ = proc.communicate()
        if proc.returncode != 0:
            self.logger.error(f'failed to objdump {self.binary}')
        return cout.decode(sys.stdout.encoding, errors='ignore')

    def parse(self):
        dump = io.StringIO(self.get_objdump_log())
        for line in dump:
            self.check_routine_start(line)
            self.check_instruction(line)
        self.new_routine(None)
        self.parsed = True

    def check_routine_start(self, line):
        ldata = line.rstrip().split()
        if len(ldata) == 2:
            name = ldata[1]
            if name.find('<') == 0 and name.find('>') == (len(name)-2):
                self.new_routine(name[1:len(name)-2])

    def check_instruction(self, line):
        if self.routine is None:
            # no routine initialized
            return
        ldata = line.rstrip().split()
        if len(ldata) >= 3:
            addr = ldata[0][:len(ldata[0])-1]
            if ldata[2][0] == '.':
                self.addrs[addr] = Bundler(addr, IType.DATA)
            else:
                self.addrs[addr] = Bundler(addr, IType.INSN)
            self.update_last_bundler(self.addrs[addr])

    def update_last_bundler(self, bundler):
        if self.last_bundler is not None:
            self.last_bundler.size = int(bundler.addr, 16) - int(self.last_bundler.addr, 16)
        self.last_bundler = bundler
        # Known: This does not compute the size of the last instruction !!!
# --------------------
class PulseUtilsMapper(MapperCore):
    '''Instruction mapper using the **pulseutils** arm binary parser.

    .. note::

       one should not create an instance directly and use :func:`Mapper` instead for uniformization.
    '''

    def parse(self):
        asm = autogen_asmdata(self.binary, ArmAsmData, objdump='arm-none-eabi-objdump')
        for label in asm.labels('.text'):
            addrs = {}
            for loc, _, itpe, size in asm.instructions(label, section='.text', details=True):
                addrs[loc] = Bundler(loc, IType.INSN if itpe == 'instruction' else IType.DATA, size)
            self.mapping[label] = addrs
        self.parsed = True
# --------------------
# --------------------
def Mapper(binary, logger, mode='pulseutils'):
    '''Utility function for obtaining a :class:`fistic.mapper.MapperCore` instruction mapper.

    :param binary: target arm binary file
    :param logger: logging utility class
    :param mode: mapper type selection, should be one of 'pulseutils' or 'legacy', default to 'pulseutils'
    :type binary: str
    :type mode: str, optional

    :return: a MapperCore instance for **binary**
    :rtype: :class:`fistic.mapper.MapperCore`

    .. note::

       useful for aggregation and for code using previous version of fistic.
    '''
    return {
        'legacy': LegacyMapper,
        'pulseutils': PulseUtilsMapper,
    }[mode](binary, logger)
# --------------------
