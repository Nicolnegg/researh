# ----------------------------------------
from pulseutils.logging import Logger
from pulseutils.assembly import x86AsmData, ArmAsmData
# ----------------------------------------
DATA_CLASS = {
    'x86': x86AsmData,
    'arm32': ArmAsmData,
}
# ----------------------------------------
class AddHookCheck:

    def __init__(self, immediate):
        self.immediate = immediate

    def __call__(self, inst, **kwargs):
        return '\tadds\t' in inst and f'#{self.immediate}' in inst
# ----------------------------------------
class AfterBlHookCheck:

    def __init__(self, symbol):
        self.symbol = symbol

    def __call__(self, inst, **kwargs):
        prev = kwargs['prev']
        return '\tbl\t' in prev and self.symbol in prev
# ----------------------------------------
class HookCheckers:

    def __getitem__(self, key):
        if key.startswith('adds:'):
            return AddHookCheck(int(key.split(':')[1]))
        if key.startswith('afterbl:'):
            return AfterBlHookCheck(key.split(':')[1])
# ----------------------------------------
HOOK_CHECKERS = HookCheckers()
# ----------------------------------------
def as_hex(v, bsize=None):
    if bsize is None:
        return '0x{:x}'.format(v)
    return ('0x{:0' + str(2*bsize) + 'x}').format(v) # TODO
# ----------------------------------------
def as_hex8(v):
    return '{:#010x}'.format(v)
# ----------------------------------------
def as_loc(l, bs):
    return '@[{},{}]'.format(as_hex8(l), bs)
# ----------------------------------------
class BinsecConfigurator:

    class Options:

        def __init__(self, isa=None, entrypoint=None):
            self.isa = isa
            self.entrypoint = entrypoint
            self.assigns = []
            self.hooks = dict(reach=[], cut=[])

    CFG_TEMPLATE = """[kernel]
isa = {0}
entrypoint = {1}

[sse]
enabled = true
depth = 100000
directives = {2}

[arm]
supported-modes = thumb

[fml]
solver = boolector
solver-timeout = 300
"""

    MEM_TEMPLATE = """
sp<32> := 0xffffffff;
t<1> := 1<1>; #thumb mode on
"""

    def __init__(self, source, asmdata, symdata, opts):
        self.source = source
        self.opts = opts
        self.asm = DATA_CLASS[self.opts.isa](source, asmdata)
        self.asm.load_symbol_table(symdata)
        self.data = dict()

    def generate(self, cfg_target, mem_target):
        self._prepare()
        self._export_cfg(cfg_target)
        self._export_mem(mem_target)

    def _prepare(self):
        self._prepare_directives()
        self._prepare_memory()

    def symbol_location(self, symbol):
        return (self.asm.address_of(symbol), self.asm.bytesize_of(symbol))

    def _prepare_directives(self):
        self.data['directives'] = []
        self._prepare_hook_directives('reach')
        self._prepare_hook_directives('cut')
        self._prepare_assume_directives()

    def _prepare_hook_directives(self, dtype):
        for symbol, rtype in self.opts.hooks[dtype]:
            pinst = ''
            for loc, inst in self.asm.instructions(symbol, '.text'):
                if HOOK_CHECKERS[rtype](inst, prev=pinst):
                    directive = '{} {}'.format(as_hex(loc), dtype)
                    self.data['directives'].append(directive)
                pinst = inst

    def _prepare_assume_directives(self):
        pass

    def _prepare_memory(self):
        self.data['memory'] = dict()
        self._prepare_memory_literals()
        self._prepare_memory_assigns()

    def _prepare_memory_literals(self):
        for loc in self.asm.literals():
            self.data['memory'][(loc, 4)] = 'file'

    def _prepare_memory_assigns(self):
        for symbol, value in self.opts.assigns:
            self.data['memory'][self.symbol_location(symbol)] = value

    def _export_cfg(self, target):
        with open(target, 'w') as stream:
            stream.write(self.CFG_TEMPLATE.format(self.opts.isa, self.opts.entrypoint, ';'.join(self.data['directives'])))

    def _export_mem(self, target):
        with open(target, 'w') as stream:
            stream.write(self.MEM_TEMPLATE)
            for loc, val in self.data['memory'].items():
                if val == 'file':
                    stream.write('{} from_file;\n'.format(as_loc(loc[0], loc[1])))
                else:
                    stream.write('{} := {};\n'.format(as_loc(loc[0], loc[1]), as_hex(val, loc[1])))
# ----------------------------------------
