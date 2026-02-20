# ----------------------------------------
import os
import os.path
import re
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
    # Drop user-defined reach_error and nondet stubs so the generated
    # SV-COMP stubs (with _stub_*_array inputs) are used consistently.
    delete_defs = { 'reach_error', 'c2bc_abort', } | {
        s.identifier for s in templates.stubs().values()
        if s.identifier.startswith('__VERIFIER_nondet_')
    }
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
            # Fallback: use reach_error / __VERIFIER_error entry if available.
            for fname in ('reach_error', '__VERIFIER_error'):
                if asm.has_function(fname):
                    for loc, _ in asm.instructions(fname):
                        res.append(loc)
                        break
                if res:
                    break
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
        main_name = 'c2bc_main' if asm.has_function('c2bc_main') else 'main'
        # OK cut locations
        for loc, inst in asm.instructions(main_name):
            if 'add' in inst and '$0x7' in inst:
                res.append(loc)
        if len(res) == 0 and main_name != 'main':
            # Fallback to original main if c2bc_main has no cut markers.
            for loc, inst in asm.instructions('main'):
                if 'add' in inst and '$0x7' in inst:
                    res.append(loc)
        if len(res) == 0:
            # No cut markers found; proceed without cuts.
            return res
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
        # Preferred positive goal: explicit success hook when available and
        # actually referenced from executable code.
        if asm.has_function('reach_success'):
            succ_loc = None
            for loc, _ in asm.instructions('reach_success'):
                succ_loc = loc
                break
            if succ_loc is not None:
                succ_hex = '0x{:x}'.format(succ_loc)
                succ_tag = '<reach_success>'
                for fname in ('c2bc_main', 'main', 'fun'):
                    if not asm.has_function(fname):
                        continue
                    for _, inst in asm.instructions(fname):
                        if succ_hex in inst or succ_tag in inst:
                            return [succ_loc]
                # If the hook exists but is not referenced (e.g., inlined safe
                # branch), fall through to branch-target heuristics below.
        # Try to use the first conditional jump target in c2bc_main/fun.
        for fname in ('c2bc_main', 'fun', 'main'):
            if not asm.has_function(fname):
                continue
            for _, inst in asm.instructions(fname):
                asm_part = inst.split('\t')[-1].strip()
                if not asm_part:
                    continue
                parts = asm_part.split()
                if len(parts) < 2:
                    continue
                op = parts[0].strip().lower()
                # Conditional jumps start with j* but exclude plain jmp.
                if not op.startswith('j') or op == 'jmp':
                    continue
                # objdump format is usually "... <tab>jne    804991e <...>".
                m = re.search(r'\b([0-9a-fA-F]{6,16})\b', asm_part)
                if m is None:
                    continue
                try:
                    return [int(m.group(1), 16)]
                except ValueError:
                    continue
        cpt = 0
        main_name = 'c2bc_main' if asm.has_function('c2bc_main') else 'main'
        for loc, _ in asm.instructions(main_name):
            cpt += 1
            if cpt > 1:
                return [loc]
        return []

    def directives(self, rlocs, clocs, alocs):
        dstr = [ 'reach 0x{:x}'.format(loc) for loc in rlocs ]
        dstr += [ 'cut at 0x{:x}'.format(loc) for loc in clocs ]
        return dstr

    def abduction_directives(self, rlocs, nrlocs, clocs, alocs):
        # New SSE script syntax: "reach 0x...", "cut at 0x..."
        #
        # For abduction, the *negative* goal must be the bug (reach_error).
        # Use rlocs (reach_hook) for negative, and pick a benign positive
        # goal from alocs (early main instruction) when available.
        dstr = []
        if alocs:
            dstr += [ '+reach 0x{:x}'.format(loc) for loc in alocs ]
        dstr += [ '-reach 0x{:x}'.format(loc) for loc in rlocs ]
        dstr += [ 'cut at 0x{:x}'.format(loc) for loc in clocs ]
        return dstr

    def initable_memlocs(self, asm):
        for label in asm.labels('.bss'):
            if 'stub' in label and (label.endswith('counter') or label.endswith('index')):
                addr = asm.address_of(label, '.bss')
                yield '@[0x{:08x},4]'.format(addr)

    def symbolic_memlocs(self, asm, symbols=set()):
        for label in asm.labels(sections=('.data', '.rodata', '.bss')):
            if label.startswith('_stub') and (label.endswith('_data') or label.endswith('_array')):
                try:
                    addr = asm.address_of(label)
                    faddr = '0x{:08x}'.format(addr)
                    size = asm.bytesize_of(label)
                except KeyError:
                    # Some symbols may miss 'align' in the objdump table.
                    size = 0
                if size <= 0 and label.endswith('_array'):
                    # Fallback for stub arrays when size info is missing.
                    fsize = self._stub_array_fallback_size(label)
                    if fsize is not None:
                        size = fsize
                if size <= 0:
                    continue
                yield label, faddr, size

    def non_symbolic_memlocs(self, asm, symbols=set()):
        for label in asm.labels(sections=('.data', '.rodata', '.bss')):
            if not (label.startswith('_stub') and (label.endswith('_data') or label.endswith('_array'))):
                try:
                    addr = asm.address_of(label)
                    faddr = '0x{:08x}'.format(addr)
                    size = asm.bytesize_of(label)
                except KeyError:
                    # Some symbols may miss 'align' in the objdump table; skip them.
                    continue
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

    def _stub_array_fallback_size(self, label):
        # _stub_<type>_array with fixed size 1024 from templates.
        import re
        m = re.match(r'^_stub_(.+)_array$', label)
        if not m:
            return None
        tname = m.group(1)
        elem_size = {
            'char': 1,
            'uchar': 1,
            'unsigned_char': 1,
            'short': 2,
            'ushort': 2,
            'int': 4,
            'uint': 4,
            'long': 4,
            'ulong': 4,
            'float': 4,
            'double': 8,
            'bool': 1,
            'pointer': 4,
        }.get(tname)
        if elem_size is None:
            return None
        return 1024 * elem_size

    def _limit_ctrl_bytes(self, label, size):
        # Keep abduction tractable: limit auto-controlled bytes from large stub arrays.
        if label.endswith('_int_array'):
            return min(size, 8)  # 2 ints max
        return size
# ----------------------------------------
class SVCompYmlConfig:

    def __init__(self, infile, stack=[]):
        self.infile = infile
        self.stack = stack
        self.cfgfile = '{}.yml'.format(os.path.splitext(infile)[0])
        if not os.path.isfile(self.cfgfile):
            default = {
                'input_files': [os.path.basename(infile)],
                'properties': [
                    {'property_file': 'reach.prp', 'expected_verdict': True},
                ],
            }
            with open(self.cfgfile, 'w') as stream:
                yaml.dump(default, stream, sort_keys=False)
            self.stack.append('created default svcomp property file {} (property reach.prp)'.format(self.cfgfile))
        self.stack.append('loading svcomp property file {}'.format(self.cfgfile))
        with open(self.cfgfile) as stream:
            self.ymldata = yaml.load(stream, Loader=ymlLoader)

    def _expect_property(self, pdata):
        prope = set()
        self.stack.append('found target property: {}'.format(pdata['property_file']))
        pname = os.path.basename(pdata['property_file'])
        if pname == 'unreach-call.prp':
            prope.add('unreachable' if pdata['expected_verdict'] else 'model')
        elif pname == 'reach.prp':
            prope.add('model' if pdata['expected_verdict'] else 'unreachable')
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

    def make_dba_command(self, source, target, function=None):
        binsec = os.environ.get('BINSEC', 'binsec')
        command = [binsec, '-disasm']
        if function:
            command += ['-disasm-functions', function]
        command += ['-disasm-o-dba', target, '-file', source]
        return command

    def write_runner(self, stream, infile, binary, config, memory, stack=[]):
        ymldat = SVCompYmlConfig(infile, stack)
        stream.write('#!/usr/bin/env bash\n')
        stream.write('echo "[c2bc] expect {}"\n'.format(ymldat.expectation))
        stream.write('tmp_script="$(mktemp)"\n')
        stream.write('trap \'rm -f "$tmp_script"\' EXIT\n')
        stream.write('cat "{}" "{}" > "$tmp_script"\n'.format(config, memory))
        stream.write('exec "${{BINSEC:-binsec}}" -sse -sse-script "$tmp_script" "{}" "$@"\n'.format(binary))

    def write_abduction_runner(self, stream, config, rconfig, memory, binary, literals, directives, asmaddr, timeout, autocontrol=False, ct_mode=False, stack=[]):
        stream.write('#!/usr/bin/env bash\n')
        stream.write('export PYTHONHASHSEED="${PYTHONHASHSEED:-0}"\n')
        stream.write('if [[ "${ABDUCE_PAPER_MODE:-0}" = "1" ]]; then\n')
        stream.write('  set -- --paper-mode "$@"\n')
        stream.write('fi\n')
        ctarg = '--ct-mode ' if ct_mode else ''
        if autocontrol:
            stream.write('exec "${{PYABDUCE:-pyabduce}}" --binsec-config {} --binsec-memory {} --binsec-binary {} --binsec-addr {} --literals {} --binsec-directives {} --binsec-timeout {} --binsec-robust --robust-config {} {}$@\n'.format(config, memory, binary, asmaddr, literals, directives, timeout, rconfig, ctarg))
        else:
            stream.write('exec "${{PYABDUCE:-pyabduce}}" --binsec-config {} --binsec-memory {} --binsec-binary {} --binsec-addr {} --literals {} --binsec-directives {} --binsec-timeout {} {}$@\n'.format(config, memory, binary, asmaddr, literals, directives, timeout, ctarg))

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

    def make_assumption_addr_param(self, asm, dba_file=None):
        # Prefer the address of the first cmp so assumptions are injected near
        # the decision point, not at reach hooks.
        if dba_file and os.path.isfile(dba_file):
            try:
                with open(dba_file, 'r') as dba:
                    for line in dba:
                        if line.startswith('#') and ' cmp ' in line:
                            parts = line.split()
                            if len(parts) >= 3 and parts[2].startswith('0x'):
                                return parts[2]
            except OSError:
                pass
        # Fallback 1: first cmp in fun/c2bc_main from disassembly.
        for fname in ('fun', 'c2bc_main', 'main'):
            if not asm.has_function(fname):
                continue
            for loc, inst in asm.instructions(fname):
                if 'cmp' in inst:
                    return '0x{:x}'.format(loc)
        # Fallback 2: function entry before branch execution.
        for fname in ('fun', 'c2bc_main', 'main'):
            if not asm.has_function(fname):
                continue
            for loc, _ in asm.instructions(fname):
                return '0x{:x}'.format(loc)
        # Final fallback: positive reach location.
        alocs = self.brules.detect_alocs(asm)
        return '0x{:x}'.format(alocs[0])

    def write_binsec_config(self, stream, asm, extra_lines=None, include_safety_directives=True):
        directives = []
        if include_safety_directives:
            rlocs = self.brules.detect_rlocs(asm)
            clocs = self.brules.detect_clocs(asm)
            alocs = self.brules.detect_alocs(asm)
            directives = self.brules.directives(rlocs, clocs, alocs)
        lines = ['starting from <c2bc_main>']
        for line in extra_lines or []:
            if line.strip():
                lines.append(line.strip())
        if directives:
            lines.append('# SSE directives (one per line, e.g. "reach 0x401000", "cut at 0x401234")')
            lines.extend(directives)
        stream.write('\n'.join(lines) + '\n')

    def write_robust_config(self, stream, asm, extra_lines=None, include_safety_directives=True):
        directives = []
        if include_safety_directives:
            rlocs = self.brules.detect_rlocs(asm)
            clocs = self.brules.detect_clocs(asm)
            alocs = self.brules.detect_alocs(asm)
            directives = self.brules.directives(rlocs, clocs, alocs)
        lines = ['starting from <c2bc_main>']
        for line in extra_lines or []:
            if line.strip():
                lines.append(line.strip())
        if directives:
            lines.append('# SSE directives (one per line, e.g. "reach 0x401000", "cut at 0x401234")')
            lines.extend(directives)
        stream.write('\n'.join(lines) + '\n')

    def write_binsec_memory(self, stream, asm, symbols, include_from_file=True):
        stream.write(self.brules.memory_template)
        if include_from_file:
            #for mloc in self.brules.initable_memlocs(asm):
            #    stream.write('{} from_file;\n'.format(mloc))
            for label, mloc, size in self.brules.non_symbolic_memlocs(asm, symbols):
                #stream.write('@[{},{}] := {}<{}>;\n'.format(mloc, size, label, size*8))
                stream.write('@[{},{}] := from_file\n'.format(mloc, size))

    def write_robust_memory(self, stream, asm, symbols, autocontrol=False, ctrlout=set(), include_from_file=True):
        stream.write(self.brules.robust_memory_template)
        if autocontrol:
            ctrlid = 0
            for label, mloc, size in self.brules.symbolic_memlocs(asm, symbols):
                base = int(mloc, 16)
                size = self.brules._limit_ctrl_bytes(label, size)
                # Prefer word-level control (4 bytes) when possible.
                if size >= 4:
                    for offset in range(0, size - (size % 4), 4):
                        offaddr = base + offset
                        cvarid = 'ctrlvar{}'.format(ctrlid)
                        ctrlid += 1
                        # Track all byte addresses for literal generation.
                        for b in range(4):
                            ctrlout.add('0x{:08x}'.format(offaddr + b))
                        stream.write('{}<32> := nondet\n'.format(cvarid))
                        stream.write('@[0x{:08x},4] := {}\n'.format(offaddr, cvarid))
                    # Handle any remaining tail bytes.
                    for offset in range(size - (size % 4), size):
                        offaddr = base + offset
                        cvarid = 'ctrlvar{}'.format(ctrlid)
                        ctrlid += 1
                        ctrlout.add('0x{:08x}'.format(offaddr))
                        stream.write('{}<8> := nondet\n'.format(cvarid))
                        stream.write('@[0x{:08x},1] := {}\n'.format(offaddr, cvarid))
                else:
                    for offset in range(size):
                        offaddr = base + offset
                        cvarid = 'ctrlvar{}'.format(ctrlid)
                        ctrlid += 1
                        ctrlout.add('0x{:08x}'.format(offaddr))
                        stream.write('{}<8> := nondet\n'.format(cvarid))
                        stream.write('@[0x{:08x},1] := {}\n'.format(offaddr, cvarid))
        if include_from_file:
            #for mloc in self.brules.initable_memlocs(asm):
            #    stream.write('{} from_file;\n'.format(mloc))
            for label, mloc, size in self.brules.non_symbolic_memlocs(asm, symbols):
                #stream.write('@[{},{}] := {}<{}>;\n'.format(mloc, size, label, size*8))
                stream.write('@[{},{}] := from_file\n'.format(mloc, size))

    def write_abduct_directives(self, stream, asm, dba_file=None):
        # Prefer explicit bug hooks for negative reach.
        rlocs = []
        cmp_addr = None
        if asm.has_function('reach_error'):
            rlocs = [asm.address_of('reach_error')]
        elif asm.has_function('__VERIFIER_error'):
            rlocs = [asm.address_of('__VERIFIER_error')]

        # DBA-derived targets are used only as fallback when no explicit bug hook exists.
        if not rlocs and dba_file and os.path.isfile(dba_file):
            rlocs = self._extract_dba_bug_targets(dba_file)
            # Also record the first cmp address to avoid cutting paths before it.
            try:
                with open(dba_file, 'r') as dba:
                    for line in dba:
                        if line.startswith('#') and ' cmp ' in line:
                            parts = line.split()
                            if len(parts) >= 3 and parts[2].startswith('0x'):
                                cmp_addr = int(parts[2], 16)
                                break
            except OSError:
                cmp_addr = None
        if not rlocs:
            rlocs = self.brules.detect_rlocs(asm)
        clocs = self.brules.detect_clocs(asm)
        if cmp_addr is not None:
            # With DBA-driven targets, avoid cuts: they can mask reachability.
            clocs = []
        alocs = self.brules.detect_alocs(asm)
        # Guard against degenerate directives (+reach == -reach), which make
        # abduction unsatisfiable by construction.
        if alocs:
            rset = set(rlocs)
            aset = set(alocs)
            if rset == aset:
                if asm.has_function('reach_error'):
                    rlocs = [asm.address_of('reach_error')]
                elif asm.has_function('__VERIFIER_error'):
                    rlocs = [asm.address_of('__VERIFIER_error')]
        nrlocs = self.brules.detect_nrlocs(asm)
        directives = self.brules.abduction_directives(rlocs, nrlocs, clocs, alocs)
        for directive in directives:
            stream.write(directive)
            stream.write('\n')

    def _entry_function_name(self, asm):
        for fname in ('c2bc_main', 'fun', 'main'):
            if asm.has_function(fname):
                return fname
        return None

    def _literal_source_functions(self, asm):
        # Use the entry and one-hop direct callees as sources for constants.
        # This keeps literals focused on program logic and avoids libc noise.
        entry = self._entry_function_name(asm)
        if entry is None:
            return []

        res = [entry]
        seen = set(res)
        addr_to_name = {}

        try:
            for lbl in asm.labels(sections=('.text',)):
                try:
                    addr_to_name[int(asm.address_of(lbl), 16)] = lbl
                except Exception:
                    continue
        except Exception:
            pass

        instr_re = re.compile(r'^(?:[0-9a-f]{2}(?:\s+[0-9a-f]{2})*)\s+([a-z.]+)\s*(.*)$')

        try:
            for _, inst in asm.instructions(entry):
                text = ' '.join(inst.lower().replace('\t', ' ').split(';')[0].split())
                imatch = instr_re.match(text)
                if imatch:
                    mnem = imatch.group(1)
                else:
                    mnem = text.split(None, 1)[0] if text else ''
                if not mnem.startswith('call'):
                    continue

                mname = re.search(r'<([^>]+)>', inst)
                if mname:
                    raw = mname.group(1).split('+', 1)[0].strip()
                    if raw not in seen and asm.has_function(raw):
                        seen.add(raw)
                        res.append(raw)
                    continue

                maddr = re.search(r'\b0x[0-9a-fA-F]+\b', inst)
                if not maddr:
                    continue
                try:
                    tgt = int(maddr.group(0), 16)
                except ValueError:
                    continue
                tname = addr_to_name.get(tgt)
                if tname and tname not in seen and asm.has_function(tname):
                    seen.add(tname)
                    res.append(tname)
        except Exception:
            pass

        return res

    def _data_symbol_sizes(self, asm):
        sizes = {}
        for label in asm.labels(sections=('.bss', '.data')):
            try:
                addr = asm.address_of(label)
                size = asm.bytesize_of(label)
            except KeyError:
                continue
            if size > 0 and addr not in sizes:
                sizes[addr] = size
        return sizes

    def _reg_to_32(self, reg):
        r = reg.lower()
        alias = {
            'al': 'eax', 'ah': 'eax', 'ax': 'eax', 'eax': 'eax',
            'bl': 'ebx', 'bh': 'ebx', 'bx': 'ebx', 'ebx': 'ebx',
            'cl': 'ecx', 'ch': 'ecx', 'cx': 'ecx', 'ecx': 'ecx',
            'dl': 'edx', 'dh': 'edx', 'dx': 'edx', 'edx': 'edx',
            'si': 'esi', 'esi': 'esi',
            'di': 'edi', 'edi': 'edi',
            'bp': 'ebp', 'ebp': 'ebp',
            'sp': 'esp', 'esp': 'esp',
        }
        return alias.get(r)

    def _infer_entry_memref_widths(self, asm):
        # Infer whether an entry memref is used as byte or word in branch logic.
        fname = self._entry_function_name(asm)
        if fname is None:
            return {}
        hints = {}
        reg_sources = {}
        byte_regs = {'al', 'ah', 'bl', 'bh', 'cl', 'ch', 'dl', 'dh'}
        word_regs = {'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp'}
        instr_re = re.compile(r'^(?:[0-9a-f]{2}(?:\s+[0-9a-f]{2})*)\s+([a-z.]+)\s*(.*)$')

        def _set_hint(addr_hex, hint):
            prev = hints.get(addr_hex)
            if prev == 'byte' and hint == 'word':
                return
            hints[addr_hex] = hint

        def _extract_reg(op):
            token = op.lower().strip().replace('%', '').replace('*', '')
            token = re.sub(r'\b(?:byte|word|dword|qword|ptr|ds|ss|cs|es|fs|gs)\b', '', token)
            token = token.replace(':', '').replace('[', '').replace(']', '').strip()
            if re.fullmatch(r'(eax|ebx|ecx|edx|esi|edi|ebp|esp|ax|bx|cx|dx|si|di|bp|sp|al|ah|bl|bh|cl|ch|dl|dh)', token):
                return token
            return None

        def _extract_addr(op):
            match = re.search(r'0x([0-9a-f]{7,16})', op.lower())
            if not match:
                return None
            return '0x{:08x}'.format(int(match.group(1), 16))

        for _, inst in asm.instructions(fname):
            text = ' '.join(inst.lower().replace('\t', ' ').split(';')[0].split())
            imatch = instr_re.match(text)
            if imatch:
                mnem = imatch.group(1)
                operands = imatch.group(2)
            else:
                parts = text.split(None, 1)
                mnem = parts[0] if parts else ''
                operands = parts[1] if len(parts) > 1 else ''
            ops = [op.strip() for op in operands.split(',')] if operands else []

            if mnem.startswith('mov') and len(ops) >= 2:
                src = ops[0]
                dst = ops[1]
                src_addr = _extract_addr(src)
                dst_addr = _extract_addr(dst)
                src_reg = _extract_reg(src)
                dst_reg = _extract_reg(dst)
                # AT&T load: mov 0xADDR,%eax
                if src_addr is not None and dst_reg is not None:
                    reg32 = self._reg_to_32(dst_reg)
                    if reg32 is not None:
                        reg_sources[reg32] = src_addr
                # Intel load: mov eax,[0xADDR]
                elif src_reg is not None and dst_addr is not None:
                    reg32 = self._reg_to_32(src_reg)
                    if reg32 is not None:
                        reg_sources[reg32] = dst_addr

            if mnem.startswith('cmp') or mnem.startswith('test'):
                if mnem.startswith('cmpb') or mnem.startswith('testb'):
                    default_hint = 'byte'
                elif mnem.startswith('cmpl') or mnem.startswith('testl'):
                    default_hint = 'word'
                else:
                    default_hint = None

                regs = []
                addrs = []
                for op in ops:
                    op_addr = _extract_addr(op)
                    op_reg = _extract_reg(op)
                    if op_addr is not None:
                        addrs.append(op_addr)
                    if op_reg is not None:
                        regs.append(op_reg)

                for addr_hex in addrs:
                    if default_hint is not None:
                        _set_hint(addr_hex, default_hint)

                for reg in regs:
                    reg32 = self._reg_to_32(reg)
                    if reg32 is None:
                        continue
                    addr_hex = reg_sources.get(reg32)
                    if addr_hex is None:
                        continue
                    if reg in byte_regs:
                        _set_hint(addr_hex, 'byte')
                    elif reg in word_regs:
                        _set_hint(addr_hex, 'word')

            # Legacy fallback for odd objdump formats with `%` registers in raw text.
            for reg in re.findall(r'%([a-z0-9]+)\b', text):
                reg32 = self._reg_to_32(reg)
                if reg32 is not None:
                    addr_hex = reg_sources.get(reg32)
                    if addr_hex is None:
                        continue
                    if reg in byte_regs:
                        _set_hint(addr_hex, 'byte')
                    elif reg in word_regs:
                        _set_hint(addr_hex, 'word')

        return hints

    def write_abduct_literals(self, stream, asm, controlled, dba_file=None):
        # Emit a non-empty literal grammar even when no controlled vars exist.
        emitted = set()
        consts_emitted = set()
        max_vars = 12
        width_hints = self._infer_entry_memref_widths(asm)
        symbol_sizes = self._data_symbol_sizes(asm)

        def _add_var(name):
            if len(emitted) >= max_vars:
                return
            if name not in emitted:
                stream.write('variable:{}\n'.format(name))
                emitted.add(name)

        def _add_word(addr_hex):
            if len(emitted) >= max_vars:
                return
            key = 'word:{}'.format(addr_hex)
            if key not in emitted:
                stream.write(key + '\n')
                emitted.add(key)

        def _normalize_addr(addr):
            if not isinstance(addr, str):
                return None
            text = addr.strip().lower()
            if not text.startswith('0x'):
                return None
            try:
                return '0x{:08x}'.format(int(text, 16))
            except ValueError:
                return None

        def _addr_kind(addr_hex):
            # Prefer branch-width hints recovered from cmp/test in entry code.
            hint = width_hints.get(addr_hex)
            if hint in ('byte', 'word'):
                return hint
            # Fallback to symbol size when available.
            try:
                ssize = symbol_sizes.get(int(addr_hex, 16))
            except ValueError:
                ssize = None
            if ssize is not None and ssize < 4:
                return 'byte'
            return 'word'

        def _add_auto_addr(addr):
            norm = _normalize_addr(addr)
            if norm is None:
                return False
            if _addr_kind(norm) == 'byte':
                _add_var(norm)
            else:
                _add_word(norm)
            return True

        def _add_const(value):
            sval = str(value).strip()
            try:
                ival = int(sval, 0) if (sval.startswith('0x') or sval.startswith('0b') or re.fullmatch(r'-?\d+', sval)) else None
            except ValueError:
                ival = None

            vals = []
            if ival is None:
                vals.append(sval)
            else:
                # Emit a single canonical word-sized form (32-bit).
                # Constants are still extracted from this binary, not hardcoded.
                vals.append('0x{:08x}'.format(ival & 0xffffffff))

            for outv in vals:
                if outv not in consts_emitted:
                    stream.write('constant:{}\n'.format(outv))
                    consts_emitted.add(outv)

        def _emit_default_word_constants():
            # Guided base bank for signed word comparisons.
            for cval in ('0x00000000', '0x00000001', '0xffffffff', '0x80000000', '0x7fffffff'):
                _add_const(cval)

        def _add_consts_from_entry_immediates():
            # Extract numeric immediates from relevant program functions so
            # constants come from this binary, not hardcoded seeds.
            fnames = self._literal_source_functions(asm)
            if not fnames:
                return
            instr_re = re.compile(r'^(?:[0-9a-f]{2}(?:\s+[0-9a-f]{2})*)\s+([a-z.]+)\s*(.*)$')

            def _norm_test_operand(op):
                op = op.strip().lower().replace('%', '')
                op = re.sub(r'\b(?:byte|word|dword|qword|ptr)\b', '', op)
                return ' '.join(op.split())

            for fname in fnames:
                try:
                    insns = asm.instructions(fname)
                except Exception:
                    continue
                for _, inst in insns:
                    text = ' '.join(inst.lower().replace('\t', ' ').split(';')[0].split())
                    imatch = instr_re.match(text)
                    if imatch:
                        mnem = imatch.group(1)
                        operands = imatch.group(2)
                    else:
                        parts = text.split(None, 1)
                        mnem = parts[0] if parts else ''
                        operands = parts[1] if len(parts) > 1 else ''
                    # Keep only comparison-like instructions to avoid
                    # stack/frame immediates (e.g., 0x14, 0x1c) unrelated to policy.
                    if not re.match(r'^(cmp|test|ucomi|comi)\b', mnem):
                        continue
                    # Common compiler lowering for "x == 0" is "test x, x"
                    # (no immediate), so add 0 explicitly for this pattern.
                    ops = [o.strip() for o in operands.split(',')] if operands else []
                    if mnem.startswith('test') and len(ops) == 2:
                        lhs = _norm_test_operand(ops[0])
                        rhs = _norm_test_operand(ops[1])
                        if lhs and lhs == rhs and '0x' not in lhs and '(' not in lhs and '[' not in lhs:
                            _add_const('0x0')
                    # Prefer AT&T immediates ($0xNN); also support Intel-like
                    # operand forms ending with ", 0xNN".
                    matches = re.findall(r'\$(-?(?:0x[0-9a-fA-F]+|\d+))', operands)
                    if not matches:
                        mm = re.search(r'(?:,|\s)(-?(?:0x[0-9a-fA-F]+|\d+))\s*$', operands)
                        if mm:
                            matches = [mm.group(1)]
                    for m in matches:
                        try:
                            val = int(m, 0)
                        except ValueError:
                            continue
                        if val < 0:
                            continue
                        _add_const('0x{:x}'.format(val))

        def _add_from_entry_memrefs():
            # Recover data addresses directly referenced by entry code
            # (typically c2bc_main) to capture true decision variables such as
            # user globals, even when auto-controlled vars only expose stubs.
            fname = self._entry_function_name(asm)
            if fname is None:
                return
            seen = set()
            ordered = []
            for _, inst in asm.instructions(fname):
                for m in re.findall(r'0x[0-9a-fA-F]{7,16}', inst):
                    mh = m.lower()
                    # Keep only likely data-segment addresses (x86 static bins
                    # used in this pipeline place data around 0x080e....).
                    if not (mh.startswith('0x080e') or mh.startswith('0x80e')):
                        continue
                    try:
                        norm = '0x{:08x}'.format(int(mh, 16))
                    except ValueError:
                        continue
                    if norm in seen:
                        continue
                    seen.add(norm)
                    ordered.append(norm)

            # If branch-width inference succeeded, keep only addresses that
            # actually influence compare/test conditions.
            if width_hints:
                ordered = [addr for addr in ordered if addr in width_hints]

            emitted_entry = 0
            for norm in ordered:
                _add_auto_addr(norm)
                emitted_entry += 1
                if len(emitted) >= max_vars or emitted_entry >= 3:
                    return

        def _add_from_dba():
            before_vars = len(emitted)
            if not dba_file or not os.path.isfile(dba_file):
                return False
            for varname, constval in self._extract_dba_vars(dba_file):
                if varname is not None:
                    if not _add_auto_addr(varname):
                        _add_var(varname)
                if constval is not None:
                    _add_const(constval)
            return len(emitted) > before_vars

        def _add_stub_index_symbols():
            # Indexed stub arrays require the index to be explicit in literals;
            # otherwise constants on array cells alone are often insufficient.
            for label in asm.labels(sections=('.bss', '.data')):
                if not re.match(r'^_stub_.*_index$', label):
                    continue
                try:
                    addr = asm.address_of(label)
                    size = asm.bytesize_of(label)
                except KeyError:
                    continue
                if size >= 4:
                    _add_word('0x{:08x}'.format(addr))
                elif size > 0:
                    for off in range(size):
                        _add_var('0x{:08x}'.format(addr + off))

        # Prefer literals extracted from DBA conditions when available.
        dba_emitted = _add_from_dba()

        # If DBA gave us real predicates (e.g., eax/ebx), keep the literal
        # set small and avoid flooding with stub-array controlled bytes.
        if dba_emitted:
            _add_stub_index_symbols()
            _add_from_entry_memrefs()
            if not consts_emitted:
                _add_consts_from_entry_immediates()
            return

        if controlled:
            for ctrlv in controlled:
                if not _add_auto_addr(ctrlv):
                    _add_var(ctrlv)
                stream.write('controlled:{}\n'.format(ctrlv))
            # Also include direct data memrefs from the main function so
            # global decision vars are not lost when controlled vars are stub-only.
            _add_from_entry_memrefs()
        else:
            # Prefer user-visible nondet/public globals when present, as they
            # usually represent the actual program inputs in SVCOMP-style
            # harnesses (e.g. __VERIFIER_nondet_slot_* and public_*).
            for label in asm.labels(sections=('.bss', '.data')):
                if not (label.startswith('__VERIFIER_nondet_slot_') or label.startswith('public_')):
                    continue
                try:
                    addr = asm.address_of(label)
                    size = asm.bytesize_of(label)
                except KeyError:
                    continue
                if size <= 0:
                    continue
                # Prefer a word-level variable when possible. This makes
                # conditions like "== 3" expressible with max-depth=1.
                if size >= 4:
                        _add_word('0x{:08x}'.format(addr))
                else:
                    for off in range(min(size, 4)):
                        _add_var('0x{:08x}'.format(addr + off))

            # Also mine direct memory references in entry code to recover
            # globals used in branch predicates (e.g., input mirrors).
            _add_from_entry_memrefs()

            # Prefer only stub-created symbolic inputs.
            for _, mloc, size in self.brules.symbolic_memlocs(asm, set()):
                base = int(mloc, 16)
                size = self.brules._limit_ctrl_bytes('stub_int_array', size)
                # Prefer word-level variables; keep byte-level only as fallback.
                if size >= 4:
                    for offset in range(0, min(size, 8), 4):
                        offaddr = '0x{:08x}'.format(base + offset)
                        _add_auto_addr(offaddr)
                    rem = min(size, 8) % 4
                    if rem:
                        start = base + (min(size, 8) - rem)
                        for b in range(rem):
                            _add_var('0x{:08x}'.format(start + b))
                else:
                    for offset in range(min(size, 4)):
                        offaddr = '0x{:08x}'.format(base + offset)
                        _add_var(offaddr)
            if not emitted:
                # Minimal fallback: pick at most one small global to avoid empty literals.
                for label in asm.labels(sections=('.bss', '.data')):
                    size = asm.bytesize_of(label)
                    if size <= 0 or size > 8:
                        continue
                    addr = asm.address_of(label)
                    for offset in range(min(size, 2)):
                        offaddr = '0x{:08x}'.format(addr + offset)
                        _add_var(offaddr)
                    break

        # Emit a compact default bank when word-level predicates are present.
        if any(str(v).startswith('word:') for v in emitted):
            _emit_default_word_constants()
        # Also keep constants observed in the binary code.
        _add_consts_from_entry_immediates()

    def _extract_dba_vars(self, dba_file):
        # Yield tuples (varname, constval) from DBA comparisons.
        import re
        results = []
        last_sub = {}

        def _strip_suffix(tok):
            return re.sub(r'<\d+>$', '', tok)

        def _normalize_operand(tok):
            tok = tok.strip()
            tok = tok.strip('()')
            tok = tok.replace('%', '')
            tok = _strip_suffix(tok)
            if tok.startswith('@[') and tok.endswith(']'):
                inner = tok[2:-1].split(',')[0].strip()
                if inner.startswith('0x'):
                    return inner, None
                return None, None
            if tok.startswith('0x') or tok.isdigit():
                return None, tok
            if re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', tok):
                return tok, None
            return None, None

        def _add_pair(op1, op2):
            v1, c1 = _normalize_operand(op1)
            v2, c2 = _normalize_operand(op2)
            if v1 or c1 or v2 or c2:
                results.append((v1, c1))
                results.append((v2, c2))

        sub_re = re.compile(r'^([A-Za-z0-9_]+)(?:<\d+>)?\s*:=\s*\(([^)]+?)\s-\s([^)]+?)\)$')
        zf_re = re.compile(r'^ZF(?:<\d+>)?\s*:=\s*\(([^)]+)\)$')
        eq_re = re.compile(r'^(0x[0-9a-fA-F]+|[A-Za-z0-9_]+)\s*=\s*(0x[0-9a-fA-F]+|[A-Za-z0-9_]+)$')
        if_re = re.compile(r'^if\s+(.+)\s+goto', re.IGNORECASE)

        with open(dba_file, 'r') as dba:
            for line in dba:
                l = line.strip()
                if not l or l.startswith('#'):
                    # Try to parse cmp comments: "# -- 0x... cmp op1, op2"
                    if l.startswith('#') and ' cmp ' in l:
                        cm = re.search(r'\bcmp\w*\s+([^,]+),\s*(.+)$', l)
                        if cm:
                            _add_pair(cm.group(1), cm.group(2))
                    continue

                msub = sub_re.match(l)
                if msub:
                    resv = _strip_suffix(msub.group(1))
                    last_sub[resv] = (msub.group(2), msub.group(3))
                    continue

                mzf = zf_re.match(l)
                if mzf:
                    expr = mzf.group(1).strip()
                    meq = eq_re.match(expr)
                    if meq:
                        left = _strip_suffix(meq.group(1))
                        right = _strip_suffix(meq.group(2))
                        resv = right if left in ('0', '0x0') else left if right in ('0', '0x0') else None
                        if resv and resv in last_sub:
                            op1, op2 = last_sub[resv]
                            _add_pair(op1, op2)
                    continue

                mif = if_re.match(l)
                if mif:
                    expr = mif.group(1).strip()
                    for op in ('<>', '=', '<s', '<u', '<=', '>=', '<', '>'):
                        if op in expr:
                            parts = expr.split(op)
                            if len(parts) == 2:
                                _add_pair(parts[0], parts[1])
                            break

        return results

    def _extract_dba_bug_targets(self, dba_file):
        # Prefer the branch target following the cmp between eax and ebx
        # (this matches nondet int comparisons in SV-COMP stubs).
        import re
        targets = []
        if_re = re.compile(r'^(?:\d+:\s*)?if\s+ZF<1>\s+goto\s+\((0x[0-9a-fA-F]+),')
        cmp_flag = False
        with open(dba_file, 'r') as dba:
            for line in dba:
                l = line.strip()
                if l.startswith('#') and ' cmp ' in l and 'ebx' in l and 'eax' in l:
                    cmp_flag = True
                    continue
                if cmp_flag:
                    mif = if_re.match(l)
                    if mif:
                        return [int(mif.group(1), 16)]
                    if l.startswith('#') and ' cmp ' in l:
                        cmp_flag = False
                else:
                    mif = if_re.match(l)
                    if mif:
                        targets.append(int(mif.group(1), 16))
        return targets
# ----------------------------------------
# ----------------------------------------
