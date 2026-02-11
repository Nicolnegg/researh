# ----------------------------------------
from pulseutils.binseccfg import BinsecConfigurator, as_hex
# ----------------------------------------
# ----------------------------------------
class PyAbduceConfigurator(BinsecConfigurator):

    class Options(BinsecConfigurator.Options):

        def __init__(self, isa=None, entrypoint=None):
            super().__init__(isa, entrypoint)
            self.hooks['nreach'] = []
            self.variables = []
            self.constants = []

    CFG_TEMPLATE = """[kernel]
isa = {0}
entrypoint = {1}

[sse]
enabled = true
depth = 100000
#directives = {2}

[arm]
supported-modes = thumb

[fml]
solver = boolector
solver-timeout = 300
"""

    def __init__(self, source, asmdata, symdata, opts):
        super().__init__(source, asmdata, symdata, opts)

    def generate(self, cfg_target, mem_target, direc_target, lit_target, env_target):
        super().generate(cfg_target, mem_target)
        self._export_direc(direc_target)
        self._export_lit(lit_target)
        self._export_env(env_target)

    def _prepare(self):
        super()._prepare()
        self._prepare_literals()

    def _prepare_directives(self):
        super()._prepare_directives()
        self._prepare_hook_directives('nreach')

    def _prepare_literals(self):
        self._prepare_literal_constants()
        self._prepare_literal_variables()

    def _prepare_literal_constants(self):
        self.data['constants'] = [ c for c in self.opts.constants ]

    def _prepare_literal_variables(self):
        self.data['variables'] = []
        for symbol in self.opts.variables:
            loc, size = self.symbol_location(symbol)
            for bloc in range(loc, loc+8*size, 8):
                self.data['variables'].append(as_hex(bloc))

    def _export_direc(self, target):
        with open(target, 'w') as stream:
            for directive in self.data['directives']:
                if directive.endswith('nreach'):
                    stream.write(f'-{directive.replace("nreach", "reach")}\n')
                elif directive.endswith('reach'):
                    stream.write(f'+{directive}\n')
                else:
                    stream.write(f'{directive}\n')

    def _export_lit(self, target):
        with open(target, 'w') as stream:
            for var in self.data['variables']:
                stream.write(f'variable:{var}\n')
            for val in self.data['constants']:
                stream.write(f'constant:{val}\n')

    def _export_env(self, target):
        with open(target, 'w') as stream:
            hackaddr = list(self.asm.instructions(self.opts.entrypoint, '.text'))[1][0]
            # Setting assumption on first addres does not work in this version of binsec
            stream.write(f'entrypoint = "{as_hex(hackaddr)}"\n')
# ----------------------------------------
# ----------------------------------------
