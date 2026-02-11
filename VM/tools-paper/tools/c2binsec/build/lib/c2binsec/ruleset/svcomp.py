# ----------------------------------------
import os.path
from pycparser import c_generator
import yaml
try:
    from yaml import CLoader as ymlLoader
except ImportError:
    from yaml import Loader as ymlLoader
from .core import GenericRuleSet
from . import svcomp_templates as templates
# ----------------------------------------
class SVCompRSDirectives:

    cpp = templates.PreprocessorParseInit
    keep_includes = { '<stdint.h>', '<stdbool.h>', }
    forward_includes = {
        '<string.h>',
        '<math.h>',
        '<float.h>',
        '<fenv.h>',
        '<limits.h>',
        '<stdlib.h>',
    }
    skip_undefined = {
        'strcmp',
        'strrchr',
        'strlen',
        'strncpy',

        'isinf',
        '__isinf',
        'sin',
        'cos',
        'fpclassify',
        'fabs',
        'isnan',
        '__isnan',
        'isfinite',
        'isnormal',
        'signbit',
        '__signbit',
        'fpclassifyf',
        '__fpclassifyf',
        'fesetround',
        'ceil',
        'rint',
        'lrint',
        'fegetround',
        'copysign',
        'fdim',
        'floor',
        'fmax',
        'fmin',
        'fmod',
        'fmodf',
        'modff',
        'nan',
        'isgreater',
        'isgreaterequal',
        'isless',
        'islessequal',
        'islessgreater',
        'isunordered',
        'nearbyint',
        'remainder',
        'round',
        'lround',
        'trunc',
        'sqrt',

        '__assert',
        '__assert_perror_fail',

        '__builtin_nan',
        '__builtin_nanf',
        '__builtin_object_size',
    }
# ----------------------------------------
class SVCompCRules:

    replace = {
        'assert' : 'c2bc_assert',
        'abort'  : 'c2bc_abort',
        'exit'   : 'c2bc_exit',

        'malloc' : 'c2bc_malloc',
        'calloc' : 'c2bc_calloc',
        'free'   : 'c2bc_free',

        'memset' : 'c2bc_memset',
        'memmove': 'c2bc_memmove',
        'memcpy' : 'c2bc_memcpy',
        'memcmp' : 'c2bc_memcmp',

        'read'   : 'c2bc_read',
        'write'  : 'c2bc_write',
        'puts'   : 'c2bc_puts',
        'printf' : 'c2bc_printf',

        '__assert_fail': 'c2bc_assert_fail',

        'main': 'c2bc_main',
    }
    delete_defs = { 'reach_error', 'c2bc_abort', }
    idstubs = ( 'LARGE_INT', )
    stubs = templates.stubs()

    def dependencies(self, ids, stack=[]):
        deps = { i for i in ids }
        for i in ids:
            if i in self.stubs:
                for dep in self.stubs[i].depends:
                    stack.append('add stub dependency {} (from {})'.format(dep, i))
                    deps.update(self.dependencies({ dep }, stack=stack))
                    # TODO: Handle ciruclar dependencies correctly
        return deps
# ----------------------------------------
class SVCompBConfig:

    config_template = templates.StandardBinsecConfig
    memory_template = templates.StandardBinsecMemory

    robust_config_template = templates.RobustBinsecConfig
    robust_memory_template = templates.RobustBinsecMemory

    reach_hook_func = 'c2bc_assert_fail'
    cut_hook_func = 'c2bc_abort'
    negative_reach_hook_func = 'c2bc_abort'

    def detect_rlocs(self, asm):
        res = []
        if asm.has_function(self.reach_hook_func):
            for loc, inst in asm.instructions(self.reach_hook_func):
                if 'add' in inst and '$0x3' in inst:
                    res.append(loc)
        if len(res) == 0:
            raise ValueError('no reach location found')
        return res

    def detect_nrlocs(self, asm):
        res = []
        if asm.has_function(self.negative_reach_hook_func):
            for loc, inst in asm.instructions(self.negative_reach_hook_func):
                if 'add' in inst and '$0x3' in inst:
                    res.append(loc)
        if len(res) == 0:
            raise ValueError('no negative reach location found')
        return res

    def detect_clocs(self, asm):
        res = []
        # OK cut locations
        for loc, inst in asm.instructions('main'):
            if 'add' in inst and '$0x7' in inst:
                res.append(loc)
        if len(res) == 0:
            raise ValueError('no main cut found')
        # Error wrapping cut locations
        if asm.has_function(self.cut_hook_func):
            for loc, inst in asm.instructions(self.cut_hook_func):
                if 'add' in inst and '$0x7' in inst:
                    res.append(loc)
            for loc, inst in asm.instructions(self.reach_hook_func):
                if 'add' in inst and '$0x7' in inst:
                    res.append(loc)
        return res

    def detect_alocs(self, asm):
        cpt = 0
        for loc, _ in asm.instructions('main'):
            cpt += 1
            if cpt > 1:
                return [loc]
        return []

    def directives(self, rlocs, clocs, alocs):
        dstr = [ '0x{:x} reach'.format(loc) for loc in rlocs ]
        dstr += [ '0x{:x} cut'.format(loc) for loc in clocs ]
        return ';'.join(dstr)

    def abduction_directives(self, rlocs, nrlocs, clocs, alocs):
        dstr = [ '+0x{:x} reach'.format(loc) for loc in rlocs ]
        dstr += [ '-0x{:x} reach'.format(loc) for loc in nrlocs ]
        dstr += [ '0x{:x} cut'.format(loc) for loc in clocs ]
        return dstr

    def initable_memlocs(self, asm):
        for label in asm.labels('.bss'):
            if 'stub' in label and (label.endswith('counter') or label.endswith('index')):
                addr = asm.address_of(label, '.bss')
                yield '@[0x{:08x},4]'.format(addr)

    def symbolic_memlocs(self, asm, symbols=set()):
        for label in asm.labels(sections=('.data', '.rodata', '.bss')):
            if label.startswith('_stub') and (label.endswith('_data') or label.endswith('_array')):
                addr = asm.address_of(label)
                faddr = '0x{:08x}'.format(addr)
                size = asm.bytesize_of(label)
                yield label, faddr, size

    def non_symbolic_memlocs(self, asm, symbols=set()):
        for label in asm.labels(sections=('.data', '.rodata', '.bss')):
            if not (label.startswith('_stub') and (label.endswith('_data') or label.endswith('_array'))):
                addr = asm.address_of(label)
                faddr = '0x{:08x}'.format(addr)
                size = asm.bytesize_of(label)
                if self._consider_symbol(label, size, symbols):
                    yield label, faddr, size

    def _consider_symbol(self, label, size, symbols):
        if size <= 0:
            return False
        if not label.startswith('_'):
            return label in symbols or label.split('.')[0] in symbols
        if label.startswith('_stub'):
            return True
        return False
# ----------------------------------------
class SVCompYmlConfig:

    def __init__(self, infile, stack=[]):
        self.infile = infile
        self.stack = stack
        self.cfgfile = '{}.yml'.format(os.path.splitext(infile)[0])
        self.stack.append('loading svcomp property file {}'.format(self.cfgfile))
        with open(self.cfgfile) as stream:
            self.ymldata = yaml.load(stream, Loader=ymlLoader)

    def _expect_property(self, pdata):
        prope = set()
        self.stack.append('found target property: {}'.format(pdata['property_file']))
        if os.path.basename(pdata['property_file']) == 'unreach-call.prp':
            prope.add('unreachable' if pdata['expected_verdict'] else 'model')
        return prope

    @property
    def expectation(self):
        exps = set()
        try:
            for pdata in self.ymldata['properties']:
                exps.update(self._expect_property(pdata))
        except KeyError as e:
            raise ValueError('could not find expected key {} in {}'.format(e, self.cfgfile))
        if len(exps) == 0:
            raise ValueError('no expected result detected in {}'.format(self.cfgfile))
        return '+'.join(exps)
# ----------------------------------------
class SVCompRuleSet(GenericRuleSet):

    def __init__(self):
        super().__init__()
        self.directives = SVCompRSDirectives()
        self.crules = SVCompCRules()
        self.brules = SVCompBConfig()

    def write_cpp_compliant(self, stream, data, stack=[]):
        stream.write(self.directives.cpp)
        fwdd = set()
        for line in data.split('\n'):
            ldata = line
            if ldata.strip().startswith('#include'):
                iname = ldata.replace('#include', '').strip()
                if iname in self.directives.keep_includes:
                    stack.append('keep include [{}]'.format(iname))
                else:
                    stack.append('remove include [{}]'.format(iname))
                    fwdd.add(iname)
                    ldata = ''
            stream.write(ldata)
            stream.write('\n')
        return fwdd

    def make_compilation_command(self, sources, target):
        return ['gcc', '-O1', '-static', '-m32', '-no-pie', '-fno-pic', '-fno-stack-protector',
                '-Werror', '-Wno-pointer-compare', '-Wno-aggressive-loop-optimizations', '-Wno-vla-larger-than',
                '-Wno-overflow', '-Wno-incompatible-pointer-types', '-Wno-int-conversion',
                '-Wno-format-security',
                '-o', target] + list(sources) + ['-lm']

    def make_disasm_command(self, source):
        return ['objdump', '-D', source]

    def make_disasm_table_command(self, source):
        return ['objdump', '-t', source]

    def write_runner(self, stream, infile, binary, config, memory, stack=[]):
        ymldat = SVCompYmlConfig(infile, stack)
        stream.write('#!/usr/bin/env bash\n')
        stream.write('echo "[c2bc] expect {}"\n'.format(ymldat.expectation))
        stream.write('exec binsec -file {} -config {} -sse-memory {} $@\n'.format(binary, config, memory))

    def write_abduction_runner(self, stream, config, rconfig, memory, binary, literals, directives, asmaddr, timeout, autocontrol=False, stack=[]):
        stream.write('#!/usr/bin/env bash\n')
        if autocontrol:
            stream.write('exec pyabduce --binsec-config {} --binsec-memory {} --binsec-binary {} --binsec-addr {} --literals {} --binsec-directives {} --binsec-timeout {} --binsec-robust --robust-config {} $@\n'.format(config, memory, binary, asmaddr, literals, directives, timeout, rconfig))
        else:
            stream.write('exec pyabduce --binsec-config {} --binsec-memory {} --binsec-binary {} --binsec-addr {} --literals {} --binsec-directives {} --binsec-timeout {} $@\n'.format(config, memory, binary, asmaddr, literals, directives, timeout))

    def build_c_prepatch(self, fdata):
        patch = []
        for iname in fdata:
            if iname in self.directives.forward_includes:
                patch.append('#include {}\n'.format(iname))
        return ''.join(patch)

    def write_c_update(self, stream, ast, data, prepatch=None, stack=[]):
        if prepatch is not None:
            stream.write(prepatch)
            stream.write('\n')
        for undecl in data.undeclared:
            try:
                stream.write(self.crules.stubs[undecl].declaration)
                stream.write('\n')
            except KeyError as e:
                kname = str(e)[1:-1]
                if kname in data.declaredptr:
                    stack.append('forward possible function ptr {}'.format(e))
                elif kname not in self.directives.skip_undefined:
                    stack.append('missing stub for function {}'.format(e))
                    raise e
        generator = c_generator.CGenerator()
        stream.write(generator.visit(ast))

    def _list_missing_stubs(self, data):
        for m in data.undefined:
            yield m
        yield 'c2bc_bss_exhibiter_keystring'

    def write_c_stubs(self, stream, data, stack=[]):
        for attribute in ('declaration', 'definition'):
            for missing in self._list_missing_stubs(data):
                try:
                    stream.write(getattr(self.crules.stubs[missing], attribute))
                    stream.write('\n')
                except KeyError as e:
                    kname = str(e)[1:-1]
                    if kname not in self.directives.skip_undefined:
                        stack.append('missing stub for function {}'.format(e))
                        raise e

    def make_assumption_addr_param(self, asm):
        alocs = self.brules.detect_alocs(asm)
        return '0x{:x}'.format(alocs[0])

    def write_binsec_config(self, stream, asm):
        rlocs = self.brules.detect_rlocs(asm)
        clocs = self.brules.detect_clocs(asm)
        alocs = self.brules.detect_alocs(asm)
        directives = self.brules.directives(rlocs, clocs, alocs)
        stream.write(self.brules.config_template.format('main', directives))

    def write_robust_config(self, stream, asm):
        rlocs = self.brules.detect_rlocs(asm)
        clocs = self.brules.detect_clocs(asm)
        alocs = self.brules.detect_alocs(asm)
        directives = self.brules.directives(rlocs, clocs, alocs)
        stream.write(self.brules.robust_config_template.format('main', directives))

    def write_binsec_memory(self, stream, asm, symbols):
        stream.write(self.brules.memory_template)
        #for mloc in self.brules.initable_memlocs(asm):
        #    stream.write('{} from_file;\n'.format(mloc))
        for label, mloc, size in self.brules.non_symbolic_memlocs(asm, symbols):
            #stream.write('@[{},{}] := {}<{}>;\n'.format(mloc, size, label, size*8))
            stream.write('@[{},{}] from_file;\n'.format(mloc, size))

    def write_robust_memory(self, stream, asm, symbols, autocontrol=False, ctrlout=set()):
        stream.write(self.brules.robust_memory_template)
        if autocontrol:
            ctrlid = 0
            for label, mloc, size in self.brules.symbolic_memlocs(asm, symbols):
                for offset in range(4):
                    offaddr = '0x{:08x}'.format(int(mloc, 16)+offset)
                    cvarid = 'ctrlvar{}'.format(ctrlid)
                    ctrlid += 1
                    #ctrlout.add(cvarid)
                    ctrlout.add(offaddr)
                    stream.write('{}<8> := nondet\n'.format(cvarid))
                    stream.write('@[{},1] := {}\n'.format(offaddr, cvarid))
        #for mloc in self.brules.initable_memlocs(asm):
        #    stream.write('{} from_file;\n'.format(mloc))
        for label, mloc, size in self.brules.non_symbolic_memlocs(asm, symbols):
            #stream.write('@[{},{}] := {}<{}>;\n'.format(mloc, size, label, size*8))
            stream.write('@[{},{}] from_file;\n'.format(mloc, size))

    def write_abduct_directives(self, stream, asm):
        rlocs = self.brules.detect_rlocs(asm)
        clocs = self.brules.detect_clocs(asm)
        alocs = self.brules.detect_alocs(asm)
        nrlocs = self.brules.detect_nrlocs(asm)
        directives = self.brules.abduction_directives(rlocs, nrlocs, clocs, alocs)
        for directive in directives:
            stream.write(directive)
            stream.write('\n')

    def write_abduct_literals(self, stream, asm, controlled):
        for ctrlv in controlled:
            stream.write('variable:{}\n'.format(ctrlv))
            stream.write('controlled:{}\n'.format(ctrlv))
# ----------------------------------------
# ----------------------------------------
