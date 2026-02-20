# -------------------$
import sys
import os
import io
import re
import subprocess
import time
import itertools
from subprocess import Popen, PIPE, STDOUT, TimeoutExpired
from datetime import datetime
import configparser
# --------------------
from . import minibinsec
from .checkers import CheckerResult, AbstractChecker
from pulseutils.files import create_directory
# --------------------
class BinsecLogChunk:

    def __init__(self, bswitch, level, data):
        self.bswitch = bswitch
        self.level = level
        self.data = data
# --------------------
class BinsecLogParser:

    def __init__(self, data, logger, robust=False, translation=None):
        self.logger = logger
        self.robust = robust

        self.translation = translation if translation is not None else dict()

        self.logdata = []
        self.models = []
        self._last_smt = None
        self._last_model = None

        self.status = {
            'goal-unreachable': False,
            'checkct-program-status': None,
            'checkct-leaks': [],
        }

        self._parse(data)

    def _parse(self, data):
        self._load_data_chunks(data)
        self._parse_chunks()

    def _load_data_chunks(self, data):
        with io.StringIO(data) as stream:
            cstart_hook = r'\[(\w+):(\w+)\]'
            logstr = stream.read()

            prev = None
            for cstart in re.finditer(cstart_hook, logstr):
                if prev is not None:
                    data = logstr[prev.end():cstart.start()-1].strip()
                    self.logdata.append(BinsecLogChunk(prev[1], prev[2], data))
                prev = cstart
            if prev is not None:
                data = logstr[prev.end():].strip()
                self.logdata.append(BinsecLogChunk(prev[1], prev[2], data))

            self.logger.debug('loaded {} data chunks'.format(len(self.logdata)))

    def _parse_chunks(self):
        for chunk in self.logdata:
            handler = '_parse_{}_chunk'.format(chunk.bswitch)
            if hasattr(self, handler):
                getattr(self, handler)(chunk)
        self._push_last_model()

    def _push_last_model(self):
        if self._last_model is not None:
            self.models.append(self._last_model)

    def _parse_sse_chunk(self, chunk):
        handler_core = chunk.data.split()[0].lower()
        handler = '_handle_sse_{}'.format(handler_core)
        if hasattr(self, handler):
            getattr(self, handler)(chunk)

    def _parse_checkct_chunk(self, chunk):
        for line in chunk.data.split('\n'):
            ldata = line.strip()
            if not ldata:
                continue
            smatch = re.search(r'Program status is\s*:\s*(secure|insecure|unknown)', ldata, re.IGNORECASE)
            if smatch is not None:
                self.status['checkct-program-status'] = smatch[1].lower()
            lmatch = re.search(r'Instruction\s+([0-9a-fx]+)\s+has\s+(.+?)\s+leak', ldata, re.IGNORECASE)
            if lmatch is not None:
                self.status['checkct-leaks'].append({
                    'instruction': lmatch[1],
                    'kind': lmatch[2].strip(),
                    'raw': ldata,
                })

    def _parse_fml_chunk(self, chunk):
        if chunk.data.startswith('Will open'):
            self._handle_smt_source(chunk)

    def _handle_smt_source(self, chunk):
        self._last_smt = chunk.data.replace('Will open ', '')
        if not os.path.isfile(self._last_smt):
            self.logger.warning('recovering unlogged smtfile: {}'.format(self._last_smt))

    def _handle_sse_model(self, chunk):
        self._push_last_model()
        hookd = r'Model @ ([0-9a-f]+)'
        mmatch = re.search(hookd, chunk.data)
        vloc = mmatch[1] if mmatch else 'Unlocated Model'
        model = self._parse_model(chunk.data)
        self._last_model = { 'loc': vloc, 'model' : model, 'enum' : None, 'smtlog': self._last_smt }

    def _handle_sse_goal(self, chunk):
        if chunk.data == 'Goal unreachable.':
            self.status['goal-unreachable'] = True

    def _parse_model(self, model):
        def _normalize_key(key):
            key = key.strip()
            if key.startswith('#x'):
                key = '0x' + key[2:]
            if '!' in key:
                key = key.split('!')[0]
            return key
        def _normalize_value(val):
            val = val.strip()
            if val.startswith('0x') or val.startswith('0b'):
                return val
            if re.fullmatch(r'[0-9a-fA-F]+', val):
                return '0x' + val
            return val
        result = dict()
        for modell in model.split('\n'):
            if ':' in modell:
                ldata = [s.strip() for s in modell.split(':')]
                if len(ldata) > 2:
                    self.logger.warning('multi-colon model var (unhandled): {}'.format(modell))
                if ';' in ldata[1] and not '(;)' in ldata[1]:
                    # parse registers
                    rname = ldata[0]
                    if rname.startswith('bs_unknown1_for_'):
                        rname = rname.replace('bs_unknown1_for_', '')
                        while rname.startswith('_'):
                            rname = rname[1:]
                    if rname.startswith('undef_AF_1___'):
                        rname = rname.replace('undef_AF_1___', '0x')
                    if '_' in rname:
                        rname = rname.split('_')[0]
                    rcontent = ldata[1].replace('{', '').replace('}', '').split(';')
                    rvalue, rsize = _normalize_value(rcontent[0]), rcontent[1].strip()
                    rname = _normalize_key(rname)
                    if not rname.startswith('dummy') and not rname.startswith('bs'):
                        result[rname] = rvalue
                    # TODO : store and use rsize?
                    #self.logger.debug('from ["{}"]: @[{}] <- {}'.format(modell, rname, rvalue))
                else:
                    # remove ASCII char resolving trailing data
                    #self.logger.debug('from ["{}"]: @[{}] <- {}'.format(modell, ldata[0], ldata[1].split()[0].strip()))
                    key = _normalize_key(ldata[0])
                    result[key] = _normalize_value(ldata[1].split()[0].strip())
        self.logger.debug('model recovered: {}'.format(result))
        for tvar in set(self.translation.keys()) & set(result.keys()):
            result[self.translation[tvar]] = result[tvar]
            result.pop(tvar)
        return result
# --------------------
def execute_command(cmd, log, timeout=None, stdin=None):
    if stdin is not None:
        stdin = stdin.encode('utf-8')
    log.debug('running: {}'.format(' '.join(cmd)))
    proc = Popen(cmd, stdout=PIPE, stderr=STDOUT, stdin=(PIPE if stdin is not None else None))
    to_status = False
    try:
        cout, cerr = proc.communicate(timeout=timeout, input=stdin)
    except TimeoutExpired:
        to_status = True
        proc.kill()
        cout, cerr = proc.communicate()
    return proc.returncode, to_status, cout.decode(sys.stdout.encoding, errors='ignore'), cerr.decode(sys.stderr.encoding, errors='ignore') if cerr is not None else None
# --------------------
class BinsecAutoCandidateGenerator:

    def __init__(self, args, checkers, stats, logger):
        self.args = args
        self.vars = set()
        self.controlled = set()
        self.operators = set()
        self.checkers = checkers
        self.stats = stats
        self.log = logger
        self.exset = None
        self.cexset = None
        self.ncoreset = None
        self.restart = False
        self._rvars = set()
        self._dyn_consts = {}
        self._max_dyn_consts_per_var = max(1, int(getattr(self.args, 'dynamic_constants_per_var', 3)))
        self._init_vars()
        self._init_varengine()

    def _init_varengine(self):
        self.checkers.var_engine = self

    def get_controlled(self):
        return { v for v in self.controlled }

    def get_uncontrolled(self):
        return { v for v in self.vars if self.checkers.context.get_type(v) != minibinsec.BVarType.Literal } - self.get_controlled()

    def set_ex_set(self, exset):
        self.exset = exset

    def set_cex_set(self, cexset):
        self.cexset = cexset

    def set_ncore_set(self, ncset):
        self.ncoreset = ncset

    def is_significant(self, elem):
        return True # TODO Check if this returned result is correct

    def _format_const_for_size(self, value, bits):
        if bits <= 0:
            return None
        mask = (1 << bits) - 1 if bits < 1024 else None
        if mask is not None:
            value &= mask
        if bits % 4 == 0:
            width = max(1, bits // 4)
            return '0x{:0{}x}'.format(value, width)
        return '0b{:b}'.format(value)

    def _seed_base_constants(self):
        sizes = set()
        for vid in self._rvars:
            if self.checkers.context.is_const(vid):
                continue
            try:
                sizes.add(self.checkers.context.get_size(vid))
            except KeyError:
                continue
        for bits in sizes:
            if bits <= 0:
                continue
            vals = [0, 1, -1]
            if bits > 1:
                vals.append((1 << (bits - 1)) - 1)   # signed max
                vals.append(-(1 << (bits - 1)))      # signed min
            for v in vals:
                cfmt = self._format_const_for_size(v, bits)
                if cfmt is None:
                    continue
                cid = self.checkers.context.declare_const(cfmt)
                self.vars.add(cid)
                self._rvars.add(cid)

    def _add_dynamic_const_from_model(self, varid, value):
        if self.checkers.context.is_const(varid):
            return
        if not isinstance(value, str):
            return
        try:
            ival = int(value, 0)
        except ValueError:
            return
        bits = self.checkers.context.get_size(varid)
        cfmt = self._format_const_for_size(ival, bits)
        if cfmt is None:
            return
        seen = self._dyn_consts.setdefault(varid, set())
        if cfmt in seen:
            return
        if len(seen) >= self._max_dyn_consts_per_var:
            return
        seen.add(cfmt)
        cid = self.checkers.context.declare_const(cfmt)
        self.vars.add(cid)

    def _init_vars(self):
        canonical_regions = list(getattr(self.checkers, 'input_regions', []))
        has_explicit_var = False

        with open(self.args.literals, 'r') as stream:
            for line in stream:
                if line.startswith('constant:'):
                    cvalue = line.strip().split(':')[1]
                    if cvalue.startswith('0b') or cvalue.startswith('0x'):
                        hexvalue = cvalue
                    else:
                        value = int(cvalue)
                        hexvalue = '0x{:x}'.format(value)
                    vid = self.checkers.context.declare_const(hexvalue)
                    self._rvars.add(vid)
                    self.vars.add(vid)
                if line.startswith('variable:'):
                    value = ':'.join(line.strip().split(':')[1:])
                    vid = self.checkers.context.declare_var(value)
                    self._rvars.add(vid)
                    self.vars.add(vid) # TODO: Might be useful to remove this when non-robust version is run
                    has_explicit_var = True
                if line.startswith('word:'):
                    addr = ':'.join(line.strip().split(':')[1:]).strip()
                    if addr:
                        vid = self.checkers.context.declare_var(f"{addr}:4")
                        self._rvars.add(vid)
                        self.vars.add(vid)
                        has_explicit_var = True
                if self.args.binsec_robust and line.startswith('controlled:'):
                    value = ':'.join(line.strip().split(':')[1:])
                    vid = self.checkers.context.declare_var(value)
                    self.controlled.add(vid)
        if not has_explicit_var:
            for base, size in canonical_regions:
                vid = self.checkers.context.declare_var('0x{:08x}:{}'.format(base, size))
                self._rvars.add(vid)
                self.vars.add(vid)
        self._seed_base_constants()
        if self.args.with_auto_constants:
            vid = self.checkers.context.declare_const('0x00')
            self.vars.add(vid)
            vid = self.checkers.context.declare_const('0x01')
            self.vars.add(vid)

    def _update_vars(self):
        def _is_covered_by_input_word(vname):
            if not isinstance(vname, str):
                return False
            if not re.fullmatch(r'0x[0-9a-fA-F]+', vname):
                return False
            try:
                addr = int(vname, 16)
            except ValueError:
                return False
            for ivar in self._rvars:
                if not isinstance(ivar, str):
                    continue
                if not ivar.startswith('0x') or ':' not in ivar:
                    continue
                base_s, size_s = ivar.split(':', 1)
                if not size_s.isdigit():
                    continue
                try:
                    base = int(base_s, 16)
                    size = int(size_s)
                except ValueError:
                    continue
                if size <= 1:
                    continue
                if base <= addr < base + size:
                    return True
            return False

        if self.args.input_variables_only:
            self.vars = self._rvars
            return
        for modelset in (self.exset, self.cexset):
            for model in modelset:
                for key, val in model.items():
                    if not key in { 'default', '*controlled' }:
                        # Skip BINSEC-internal symbols (e.g., from_file!1).
                        if '!' in key:
                            continue
                        # Skip BINSEC pseudo source symbol used by memory
                        # initializers; it's not a real program variable.
                        if key == 'from_file':
                            continue
                    #if (key.startswith('0x') or
                    #    (key != 'default' and int(val, 16) != 0)):
                        # Commented version looks for non null registers only
                        if not self.checkers.fully_assumed(key):
                            # Avoid exploding the search space with byte vars
                            # when the same memory is already tracked as an
                            # input word variable (e.g. 0xADDR:4).
                            if _is_covered_by_input_word(key):
                                continue
                            self.checkers.context.declare_var(key)
                            self.vars.add(key)
                    if key in self.checkers.context.vars:
                        self._add_dynamic_const_from_model(key, val)

    def _update_operators(self):
        # TODO : Use a config file instead
        self.operators.add(minibinsec.Operator.Equal)
        if self.args.with_disequalities:
            self.operators.add(minibinsec.Operator.Distinct)
        if self.args.with_inequalities:
            self.operators.add(minibinsec.Operator.Lower)

    def _reduce_auto(self, varset):
        # In robust mode, allow controlled vars in literal generation; otherwise
        # we can end up with no relational literals for abduction.
        if self.args.binsec_robust:
            return set(varset)
        return { v for v in varset if not v in self.controlled }

    def _generate_literals(self):
        def _resized_const(const_id, target_size):
            # Build a same-width constant to avoid mixed-size pretty-printing
            # ("0x..::...") that BINSEC may reject in assume clauses.
            if target_size <= 0:
                return None
            cstr = self.checkers.context.vars[const_id][0].core
            try:
                ival = int(cstr, 0)
            except ValueError:
                return None
            mask = (1 << target_size) - 1 if target_size < 1024 else None
            if mask is not None:
                ival &= mask
            if target_size % 4 == 0:
                width = max(1, target_size // 4)
                nstr = '0x{:0{}x}'.format(ival, width)
            else:
                nstr = '0b{:b}'.format(ival)
            nid = self.checkers.context.declare_const(nstr)
            self.vars.add(nid)
            return nid

        def _normalize_pair(v1, v2):
            s1, s2 = self.checkers.context.get_size(v1), self.checkers.context.get_size(v2)
            if s1 == s2:
                return v1, v2
            c1, c2 = self.checkers.context.is_const(v1), self.checkers.context.is_const(v2)
            if c1 and not c2:
                nv1 = _resized_const(v1, s2)
                return (nv1, v2) if nv1 is not None else (None, None)
            if c2 and not c1:
                nv2 = _resized_const(v2, s1)
                return (v1, nv2) if nv2 is not None else (None, None)
            return None, None

        def _var_sort_key(varid):
            try:
                sz = self.checkers.context.get_size(varid)
            except Exception:
                sz = 0
            if self.checkers.context.is_const(varid):
                return (2, -sz, str(varid))
            # Prefer wider (word-level) variables first.
            if sz >= 32:
                return (0, -sz, str(varid))
            return (1, -sz, str(varid))

        lits = []
        ordered_vars = sorted(self._reduce_auto(self.vars), key=_var_sort_key)
        for op in self.operators:
            if op != minibinsec.Operator.Lower:
                for var1, var2 in itertools.combinations(ordered_vars, 2):
                    var1, var2 = _normalize_pair(var1, var2)
                    if var1 is None or var2 is None:
                        continue
                    if self.checkers.context.is_const(var1) and self.checkers.context.is_const(var2):
                        continue
                    # Keep only width-safe comparisons after normalization.
                    if self.checkers.context.get_size(var1) != self.checkers.context.get_size(var2):
                        continue
                    if self.args.no_variables_binop and (not self.checkers.context.is_const(var1)) and (not self.checkers.context.is_const(var2)):
                        continue
                    if self.args.core_literals:
                        literal = self.checkers.context.create_binary_term(op, var1, var2)
                        if not literal in self.ncoreset:
                            lits.append(literal)
                    if self.args.separate_bytes:
                        lits.extend(self._generate_byte_literals(op, var1, var2))
                    if self.args.separate_bits:
                        lits.extend(self._generate_bit_literals(op, var1, var2))
            else:
                for var1, var2 in itertools.permutations(ordered_vars, 2):
                    var1, var2 = _normalize_pair(var1, var2)
                    if var1 is None or var2 is None:
                        continue
                    if self.checkers.context.is_const(var1) and self.checkers.context.is_const(var2):
                        continue
                    # Keep inequalities type-safe too.
                    if self.checkers.context.get_size(var1) != self.checkers.context.get_size(var2):
                        continue
                    if self.args.no_variables_binop and (not self.checkers.context.is_const(var1)) and (not self.checkers.context.is_const(var2)):
                        continue
                    if self.args.core_literals:
                        literal = self.checkers.context.create_binary_term(op, var1, var2)
                        if not literal in self.ncoreset:
                            lits.append(literal)
                    # TODO: byte and bit separation for inequalities
        return lits

    def _generate_byte_literals(self, op, var1, var2):
        lits = []
        var1s, var2s = self.checkers.context.get_size(var1), self.checkers.context.get_size(var2)
        var1t, var2t = self.checkers.context.get_type(var1), self.checkers.context.get_type(var2)
        if var1s != var2s:
            var1bytes = self.checkers.context.create_bytes(var1) if var1s > 8 and var1t != minibinsec.BVarType.Literal else []
            var2bytes = self.checkers.context.create_bytes(var2) if var2s > 8 and var2t != minibinsec.BVarType.Literal else []
            if len(var1bytes) == 0 and len(var2bytes) != 0:
                var1bytes = [var1]
            if len(var1bytes) != 0 and len(var2bytes) == 0:
                var2bytes = [var2]
            for var1byte in var1bytes:
                for var2byte in var2bytes:
                    literal = self.checkers.context.create_binary_term(op, var1byte, var2byte)
                    if not literal in self.ncoreset:
                        lits.append(literal)
        return lits

    def _generate_bit_literals(self, op, var1, var2):
        lits = []
        var1s, var2s = self.checkers.context.get_size(var1), self.checkers.context.get_size(var2)
        var1t, var2t = self.checkers.context.get_type(var1), self.checkers.context.get_type(var2)
        if var1s != var2s:
            var1bits = self.checkers.context.create_bits(var1) if var1t != minibinsec.BVarType.Literal else []
            var2bits = self.checkers.context.create_bits(var2) if var2t != minibinsec.BVarType.Literal else []
            if len(var1bits) == 0 and len(var2bits) != 0:
                var1bits = [var1]
            if len(var1bits) != 0 and len(var2bits) == 0:
                var2bits = [var2]
            for var1bit in var1bits:
                for var2bit in var2bits:
                    literal = self.checkers.context.create_binary_term(op, var1bit, var2bit)
                    if not literal in self.ncoreset:
                        lits.append(literal)
        return lits

    def restart_local_generation(self):
        self.restart = True

    def generate(self):
        old_length = 0
        self.restart = False
        self._update_vars()
        # Initial try with no constraint
        yield set()
        while True:
            self._update_vars()
            self.log.debug(f'loaded variables: {self.vars}')
            new_length = len(self.vars)
            self.stats.generation.restart += 1
            self.stats.generation.vars = new_length
            if not self.restart and new_length == old_length:
                break
            if self.restart:
                self.log.debug('externally triggered restart')
                self.restart = False
            self.log.info('restart vars->literal generation')
            old_length = new_length
            self._update_operators()
            lits = self._generate_literals()
            self.stats.generation.literals = len(lits)
            if self.args.lit_ordering:
                mtable = { lit : (-sum(self.checkers.check_satisfied({lit}, model)[0] for model in self.exset), lit.complexity()) for lit in lits }
                self.log.debug('literals ordering table: {}'.format(mtable))
                lits.sort(key=lambda lit: mtable[lit])
            self.log.debug('literals list: {}'.format(lits))
            for depth in range(2):
                # Initial max2 to redetect variables on necessary checks
                # TODO: This exploration algorithm must be reworked
                for candidate in itertools.combinations(lits, depth):
                    yield set(c for c in candidate)
                    if self.restart:
                        break
                if self.restart:
                    break
        rangeout = self.args.max_depth + 1 if self.args.max_depth is not None else len(lits) + 1
        for depth in range(2, rangeout):
            for candidate in itertools.combinations(lits, depth):
                yield set(c for c in candidate)
# --------------------
class BinsecCheckers(AbstractChecker):

    Temporary_Binsec_Configfile = 'temp.binsec.{}.script'

    def __init__(self, args, stats, logger):
        super().__init__(args, stats, logger)
        self.config = self._load_config()
        self.directives = self._load_directives()
        self.binary = self.args.binsec_binary
        self.addr = self.args.binsec_addr
        self.configdir = self.args.binsec_config_logdir
        create_directory(self.configdir)
        self.context = minibinsec.Context(self.log)
        self.var_engine = None
        self.ct_history = []
        self.ct_last = None
        self.input_regions = self._load_input_regions()
        if self.input_regions:
            self.log.debug('canonical input regions: {}'.format(self.input_regions))

    def _load_config(self):
        # Strip reach/cut/assume directives from the base config so abduction
        # controls goals exclusively via binsec_directives.
        lines = []
        with open(self.args.binsec_config, 'r') as stream:
            for line in stream:
                ldata = line.strip()
                if ldata.startswith('reach ') or ldata.startswith('cut ') or ldata.startswith('at '):
                    continue
                lines.append(line.rstrip())
        return '\n'.join(lines).strip() + '\n'

    def _normalize_directive(self, line):
        ldata = line.strip()
        if not ldata:
            return None
        if ldata.startswith('#'):
            return None
        # legacy formats
        if ldata.startswith('0x') and ' reach' in ldata:
            addr = ldata.split()[0]
            return 'reach {}'.format(addr)
        if ldata.startswith('0x') and ' cut' in ldata:
            addr = ldata.split()[0]
            return 'cut at {}'.format(addr)
        if ldata.startswith('0x') and ' assume ' in ldata:
            addr, _, expr = ldata.partition(' assume ')
            return 'at {} assume {}'.format(addr.strip(), expr.strip())
        # already in SSE script syntax
        return ldata

    def _normalize_memory_line(self, line):
        ldata = line.strip().rstrip(';')
        if not ldata:
            return None
        if ldata.startswith('controlled '):
            # legacy keyword, ignore here (robust uses nondet instead)
            return None
        # Normalize legacy "load @[addr,size] from file" syntax to BINSEC SSE memory form.
        if ldata.startswith('load @[') and ' from file' in ldata:
            # Example: "load @[0x080e4f4c,4] from file"
            ldata = ldata.replace('load ', '').replace(' from file', '')
            return '{} := from_file'.format(ldata)
        if 'from_file' in ldata and ldata.startswith('@['):
            # Keep BINSEC-native syntax for file-backed memory initialization.
            return ldata
        return ldata

    def _load_memory_input_regions(self):
        regions = []
        memfile = getattr(self.args, 'binsec_memory', None)
        if not memfile or not os.path.isfile(memfile):
            return regions
        pat = re.compile(r'^@\[(0x[0-9a-fA-F]+),([0-9]+)\]\s*:=\s*from_file\b')
        with open(memfile, 'r') as stream:
            for line in stream:
                norm = self._normalize_memory_line(line)
                if not norm:
                    continue
                m = pat.match(norm.strip())
                if m is None:
                    continue
                try:
                    base = int(m.group(1), 16)
                    size = int(m.group(2))
                except ValueError:
                    continue
                if size > 0:
                    regions.append((base, size))
        return regions

    def _load_symbol_input_regions(self):
        regions = []
        if not self.binary or not os.path.isfile(self.binary):
            return regions
        try:
            proc = subprocess.run(
                ['objdump', '-t', self.binary],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                check=False,
            )
        except Exception:
            return regions
        if proc.returncode != 0:
            return regions
        for line in proc.stdout.splitlines():
            parts = line.split()
            if len(parts) < 6:
                continue
            addr_s, size_s, name = parts[0], parts[4], parts[5]
            if not re.fullmatch(r'[0-9a-fA-F]{8}', addr_s):
                continue
            if not re.fullmatch(r'[0-9a-fA-F]{8}', size_s):
                continue
            if not (
                name.startswith('__VERIFIER_nondet_slot')
                or name.startswith('public_')
                or name == '_stub_int_array'
                or re.match(r'^_stub_.*_index$', name)
            ):
                continue
            base = int(addr_s, 16)
            size = int(size_s, 16)
            if size > 0:
                regions.append((base, size))
        return regions

    def _chunk_input_regions(self, regions):
        # Keep the model small and word-centric.
        max_bytes = max(4, int(getattr(self.args, 'input_region_max_bytes', 32)))
        seen = set()
        out = []
        for base, size in sorted(regions):
            if size <= 0:
                continue
            size = min(size, max_bytes)
            nwords = size // 4
            for idx in range(nwords):
                key = (base + 4 * idx, 4)
                if key not in seen:
                    seen.add(key)
                    out.append(key)
            rem = size % 4
            if rem:
                key = (base + (size - rem), rem)
                if key not in seen:
                    seen.add(key)
                    out.append(key)
        return out

    def _load_input_regions(self):
        # Merge symbolic/user-facing regions and from_file regions so index
        # controls are not dropped when symbols are present.
        sym_regions = self._load_symbol_input_regions()
        mem_regions = self._load_memory_input_regions()
        base = sym_regions + mem_regions
        if not base:
            return []
        return self._chunk_input_regions(base)

    def _var_to_addr_size(self, varid):
        if not isinstance(varid, str):
            return None, None
        m = re.match(r'^(0x[0-9a-fA-F]+):([0-9]+)$', varid)
        if m is None:
            return None, None
        try:
            return int(m.group(1), 16), int(m.group(2))
        except ValueError:
            return None, None

    def _compose_word_from_bytes(self, model, base, size):
        if size <= 0:
            return None
        acc = 0
        for off in range(size):
            bkey = '0x{:08x}'.format(base + off)
            if bkey not in model:
                return None
            try:
                bval = int(str(model[bkey]), 0) & 0xff
            except ValueError:
                return None
            acc |= (bval << (8 * off))
        width = max(1, size * 2)
        return '0x{:0{}x}'.format(acc, width)

    def _build_script(self, directives, memory_rules=None):
        lines = []
        lines.append(self.config.strip())
        if memory_rules is not None:
            lines.extend(memory_rules)
        lines.extend(directives)
        return '\n'.join(l for l in lines if l).strip() + '\n'

    def _load_directives(self):
        if self.args.binsec_directives is None:
            directives = { 'all': [], 'negative': [], 'positive': [] }
            self.log.debug('loaded binsec directives: {}'.format(directives))
            return directives
        with open(self.args.binsec_directives, 'r') as stream:
            result = []
            result_u = []
            result_r = []
            for line in stream:
                ldata = line.strip()
                if ldata.startswith('+'):
                    norm = self._normalize_directive(ldata[1:].strip())
                    if norm:
                        result_r.append(norm)
                elif ldata.startswith('-'):
                    norm = self._normalize_directive(ldata[1:].strip())
                    if norm:
                        result_u.append(norm)
                else:
                    norm = self._normalize_directive(ldata)
                    if norm:
                        result.append(norm)
            directives = { 'all': result, 'negative': result_u, 'positive': result_r }
            self.log.debug('loaded binsec directives: {}'.format(directives))
            return directives

    def _get_local_cfname(self):
        timestamp = datetime.now().strftime('%Y-%m-%d.%H-%M-%S.%f')
        filename = self.Temporary_Binsec_Configfile.format(timestamp)
        return os.path.join(self.configdir, filename)

    def _format_solution_set(self, solutions):
        return ('!({})'.format(' & '.join(['({})'.format(c) for c in s]) if len(s) > 0 else '0x0=0x0') for s in solutions) # 0x0=0x0 is Hack for True
        #return '!({})'.format('|'.join(['({})'.format(' & '.join(['({})'.format(c) for c in s])) for s in solutions]))

    def fully_assumed(self, addr):
        for directive in self.directives['all']:
            if 'assume' in directive:
                # TODO: Unsafe, many cases not handled
                if addr in directive and ' = ' in directive:
                    return True

    def check_goals(self, candidate):
        if getattr(self.args, 'ct_mode', False):
            return self._check_ct_goals(candidate)
        '''True when forall neg -> unreachable but exists not neg -> reachable'''
        status, model, gcore = self._check_ngoal_unreachable(candidate)
        statusr, modelr, rcore = True, None, None
        if status:
            self.stats.get_oracle('binsec-unsat-consistent').calls += 1
            statusr, modelr, rcore = self._check_dgoal_reachable(candidate)
        return status, statusr, model, modelr, gcore, rcore

    def check_necessity(self, solutions):
        if getattr(self.args, 'ct_mode', False):
            self.log.debug('necessary condition check (ct mode)')
            if any(len(sol) == 0 for sol in solutions):
                # "true" policy already covers all inputs.
                return True
            constraint = self._format_solution_set(solutions)
            status, leaks, _ = self._check_ct_candidate(constraint, [], formatted=False)
            if status == 'unknown':
                self.log.warning('ct necessity check is unknown; treating as non-necessary')
                return False
            # Necessary when the complement of current solutions is insecure.
            return status == 'insecure'
        self.log.debug('necessary condition check')
        if any(len(sol) == 0 for sol in solutions):
            # In classic mode too: once "true" is in the solution set, the
            # policy is trivially necessary and sufficient.
            return True
        # In classic mode, necessity means: outside current solutions
        # (i.e. under the negated disjunction), the positive goal is unreachable.
        # Reuse the reachability helper so "reach ... then print model" is
        # enforced; otherwise parser.models may stay empty even when reachable.
        constraint = self._format_solution_set(solutions)
        reachable, _model, _core = self._check_dgoal_reachable_util(constraint, [])
        return not reachable

    def check_vulnerability(self, candidate, reject, complete=False):
        if getattr(self.args, 'ct_mode', False):
            self.log.debug('vulnerability check (ct mode)')
            status, leaks, _ = self._check_ct_candidate(candidate, reject, complete=complete)
            if status == 'insecure':
                return True, {}, None
            if status == 'unknown':
                self.log.warning('ct vulnerability check returned unknown')
            return False, None, None
        self.log.debug('vulnerability check')
        return self._check_dgoal_reachable_util(candidate, reject, complete)

    def _sanitize_model(self, model):
        if not model:
            return model
        # Drop BINSEC SSA/internal bindings (e.g., from_file!1) that cannot
        # be serialized back as valid assumptions in SSE scripts.
        cmodel = {k: v for k, v in model.items() if k != 'default' and '!' not in k}
        # Canonicalize byte models to word-level vars when possible.
        for varid in list(self.context.vars.keys()):
            base, size = self._var_to_addr_size(varid)
            if base is None or size is None:
                continue
            if varid in cmodel:
                continue
            wval = self._compose_word_from_bytes(cmodel, base, size)
            if wval is not None:
                cmodel[varid] = wval
        return cmodel

    def _check_dgoal_reachable_util(self, candidate, reject, complete=False):
        directives = [ d for d in self.directives['all'] ]
        directives.extend(self.directives['positive'])
        # Ensure BINSEC prints a model when the goal is reachable.
        directives = [
            (d + ' then print model') if d.startswith('reach ') and 'then print model' not in d else d
            for d in directives
        ]
        for example in reject:
            directive_op = minibinsec.Operator.And if complete else minibinsec.Operator.Or
            rdir = self._generate_rejection_directive(example, op=directive_op)
            if rdir:
                directives.append(rdir)
        parser = self._run_binsec_command(candidate, directives)
        status = len(parser.models) > 0
        model = parser.models[0]['model'] if len(parser.models) > 0 else None
        model = self._sanitize_model(model)
        return status, model, None

    def _check_dgoal_reachable(self, candidate):
        return self._check_dgoal_reachable_util(candidate, [])

    def _check_ngoal_unreachable(self, candidate):
        directives = [ d for d in self.directives['all'] ]
        directives.extend(self.directives['negative'])
        # Ensure BINSEC prints a model for negative goal reachability checks.
        directives = [
            (d + ' then print model') if d.startswith('reach ') and 'then print model' not in d else d
            for d in directives
        ]
        parser = self._run_binsec_command(candidate, directives)
        status = parser.status['goal-unreachable'] or len(parser.models) <= 0
        model = parser.models[0]['model'] if len(parser.models) > 0 else None
        model = self._sanitize_model(model)
        if not status and model is None:
            self.log.warning('binsec test returned neither model nor unreachable')
            # TODO: Handle unknown case (such as timeouts)
        return status, model, None

    def negate(self, candidate):
        ncandidate = { self.context.create_negation(candidate) }
        return ncandidate

    def as_literal(self, model, coreop=minibinsec.Operator.Equal, op=minibinsec.Operator.And):
        data = []
        for key, val in model.items():
            if key != 'default':
                data.append(self.context.create_var_assignment(coreop, key, val))
        return data[0] if len(data) == 1 else self.context.create_multiterm(op, data)

    def _generate_rejection_directive(self, model, op=minibinsec.Operator.Or):
        # Skip empty models; otherwise produce a well-formed SSE assume.
        if not model:
            return None
        # Only keep variables that exist in the current context to avoid
        # leaking internal BINSEC symbols (e.g., from_file!, ctrlvar!).
        filtered = { k: v for k, v in model.items() if k in self.context.vars }
        if not filtered:
            return None
        lit = self.as_literal(filtered, coreop=minibinsec.Operator.Distinct, op=op)
        if not lit:
            return None
        return 'at {} assume {}'.format(self.addr, lit)

    def _ct_directives(self):
        # Keep only non-goal directives for CHECKCT mode.
        directives = []
        for directive in self.directives.get('all', []):
            if directive.startswith('reach ') or directive.startswith('cut '):
                continue
            directives.append(directive)
        return directives

    def _record_ct_result(self, status, leaks, timeout, attempt):
        data = {
            'status': status,
            'leaks': list(leaks),
            'timeout': timeout,
            'attempt': attempt,
            'timestamp': datetime.now().isoformat(),
        }
        self.ct_last = data
        self.ct_history.append(data)

    def _check_ct_candidate(self, candidate, reject, complete=False, formatted=False):
        directives = self._ct_directives()
        for example in reject:
            directive_op = minibinsec.Operator.And if complete else minibinsec.Operator.Or
            rdir = self._generate_rejection_directive(example, op=directive_op)
            if rdir:
                directives.append(rdir)

        retries = max(0, getattr(self.args, 'ct_unknown_retries', 1))
        timeout = self.args.binsec_timeout
        factor = max(1.0, float(getattr(self.args, 'ct_unknown_timeout_factor', 2.0)))

        parser = None
        status = 'unknown'
        leaks = []
        for attempt in range(retries + 1):
            parser = self._run_binsec_command(candidate, [d for d in directives], formatted=formatted, checkct=True, timeout_override=timeout)
            status = parser.status.get('checkct-program-status') or 'unknown'
            leaks = parser.status.get('checkct-leaks', [])
            self._record_ct_result(status, leaks, timeout, attempt)
            if status != 'unknown' or attempt >= retries:
                break
            if timeout is not None:
                timeout = max(timeout + 1, int(timeout * factor))
            self.log.warning('checkct status is unknown; retrying with timeout {}'.format(timeout))

        self.log.info('checkct status: {}'.format(status))
        for leak in leaks:
            self.log.result('checkct leak: {}'.format(leak.get('raw', 'unknown leak')))

        return status, leaks, parser

    def _check_ct_goals(self, candidate):
        status, leaks, _ = self._check_ct_candidate(candidate, [])
        if status == 'secure':
            return True, True, {}, {}, None, None
        if status == 'insecure':
            return False, False, {}, None, None, None
        # unknown: non-conclusive
        return False, False, None, None, None, None

    def evaluate_ct_policy(self, candidate):
        # Public helper for final validation/reporting.
        status, leaks, _ = self._check_ct_candidate(candidate, [])
        return {
            'status': status,
            'leaks': list(leaks),
        }

    def _run_binsec_command(self, candidate, directives, formatted=False, checkct=False, timeout_override=None):
        self.stats.get_oracle('binsec').calls += 1
        # Normalize/guard assumption lines to avoid generating invalid BINSEC scripts.
        def _append_assumption(expr):
            if expr is None:
                return
            expr = str(expr).strip()
            if not expr:
                return
            # If already a full directive, normalize it.
            if expr.startswith('at ') or (expr.startswith('0x') and ' assume ' in expr):
                norm = self._normalize_directive(expr)
                if norm and ' assume ' in norm and not norm.rstrip().endswith(' assume'):
                    directives.append(norm)
                return
            # Otherwise, attach to the configured assumption address.
            directives.append('at {} assume {}'.format(self.addr, expr))

        if formatted:
            _append_assumption(candidate)
        else:
            for assump in candidate:
                _append_assumption(assump)
        local_config_file = self._get_local_cfname()
        memory_rules = []
        with open(self.args.binsec_memory, 'r') as stream:
            for line in stream:
                rule = self._normalize_memory_line(line)
                if rule:
                    memory_rules.append(rule)
        script = self._build_script(directives, memory_rules=memory_rules)
        with open(local_config_file, 'w') as stream:
            stream.write(script)
        binsec = os.environ.get('BINSEC', 'binsec')
        run_timeout = self.args.binsec_timeout if timeout_override is None else timeout_override
        command = [binsec, '-sse']
        if checkct or getattr(self.args, 'ct_mode', False):
            command.append('-checkct')
        command += ['-sse-script', local_config_file, self.binary]
        if run_timeout is not None:
            command += ['-sse-timeout', str(run_timeout)]
        btime = time.time()
        rc, to, out, err = execute_command(command, self.log, timeout=run_timeout)
        atime = time.time()
        if to:
            self.log.warning('command timeouted')
            self.stats.get_oracle('binsec').timeouts += 1
        elif rc != 0:
            self.log.warning('command failed')
            self.stats.get_oracle('binsec').crashes += 1
        else:
            self.stats.get_oracle('binsec').times.append(atime - btime)
        parser = BinsecLogParser(out, self.log)
        if self.args.binsec_delete_configs:
            os.remove(local_config_file)
        return parser

    def check_consistency(self, candidate):
        self.stats.get_oracle('minibinsec').calls += 1
        return minibinsec.check_sat(candidate, self.context), None, None

    def _collect_candidate_vars(self, term, out):
        # Walk minibinsec term trees and collect base variable ids.
        if hasattr(term, 'terms'):
            for sub in term.terms:
                self._collect_candidate_vars(sub, out)
            return
        if hasattr(term, 'var1') and hasattr(term, 'var2'):
            self._collect_candidate_vars(term.var1, out)
            self._collect_candidate_vars(term.var2, out)
            return
        if hasattr(term, 'var'):
            self._collect_candidate_vars(term.var, out)
            return
        core = getattr(term, 'core', None)
        if isinstance(core, str):
            out.add(core)

    def _model_covers_candidate(self, candidate, model):
        # Reject pre-checks based on partial models (e.g. {"from_file": ...})
        # that do not bind variables used by the candidate.
        if 'default' in model:
            return True
        cvars = set()
        for lit in candidate:
            self._collect_candidate_vars(lit, cvars)
        cvars = {
            v for v in cvars
            if not self.context.is_const(v)
            and not self.context.is_byte_restriction(v)
            and not self.context.is_bit_restriction(v)
        }
        if not cvars:
            return True
        return all(v in model for v in cvars)

    def check_satisfied(self, candidate, model):
        self.stats.get_oracle('minibinsec').calls += 1
        if not model:
            return False, None, None
        model = { k: v for k, v in model.items() if ('!' not in k and k in self.context.vars) }
        if not model:
            return False, None, None
        if not self._model_covers_candidate(candidate, model):
            return False, None, None
        return minibinsec.check_sat_model(candidate, model, self.context), None, None

    def _precheck_consequence(self, implicant, implicate):
        '''only works for conjunctions'''
        return implicate.issubset(implicant)

    def check_consequence(self, implicant, implicate, mode_override=None):
        if self._precheck_consequence(implicant, implicate):
            return True, None, None
        if mode_override == 'exact' or self.args.consequence_checks_mode == 'exact':
            self.stats.get_oracle('minibinsec').calls += 1
            return minibinsec.check_consequence(implicant, implicate, self.context), None, None
        return False, None, None
# --------------------
class BinsecMemory:

    def __init__(self, context):
        self.context = context
        self.rules = []
        self.controlled = {}

    @property
    def translator(self):
        return { dvar.split('<')[0] : self.expandtl(dval) for dvar, dval in self.controlled.items() }

    def expandtl(self, val):
        return val.core

    def add_rule(self, rule):
        self.rules.append(rule)

    def set_controlled(self, controlled):
        varid = 0
        self.controlled.clear()
        for control in controlled:
            dvar = 'dvar{}<{}>'.format(varid, self.context.get_size(control))
            varid += 1
            self.controlled[dvar] = self.context.vars[control][0]

    def write(self, stream):
        for control, real in self.controlled.items():
            stream.write('{} := nondet\n'.format(control))
            stream.write('{} := {}\n'.format(real, control))
        for rule in self.rules:
            ldata = rule.strip().rstrip(';')
            if not ldata:
                continue
            # Keep BINSEC-native "from_file" assignments.
            stream.write(ldata)
            stream.write('\n')
# --------------------
class RobustBinsecCheckers(BinsecCheckers):

    Temporary_Binsec_Memoryfile = 'temp.binsec.{}.memory'

    def __init__(self, args, stats, logger):
        super().__init__(args, stats, logger)
        self.memory = self._load_memory()
        self.robust_config = self._load_robust_config()

    def _load_robust_config(self):
        with open(self.args.robust_config, 'r') as stream:
            return stream.read()

    def _load_memory(self):
        memory = BinsecMemory(self.context)
        with open(self.args.binsec_memory, 'r') as stream:
            for line in stream:
                memory.add_rule(line.strip())
        return memory

    def check_goals(self, candidate):
        '''True when forall neg -> unreachable but exists not neg -> reachable'''
        status, model, gcore = self._check_ngoal_unreachable(candidate)
        statusr, modelr, rcore = True, None, None
        if status:
            self.stats.get_oracle('binsec-unsat-consistent').calls += 1
            statusr, modelr, rcore = self._check_dgoal_reachable(candidate)
            if statusr:
                status, modelf, fcore = self._check_dgoal_robust(candidate)
        return status, statusr, model, modelr, gcore, rcore

    def _get_local_mename(self):
        timestamp = datetime.now().strftime('%Y-%m-%d.%H-%M-%S.%f')
        filename = self.Temporary_Binsec_Memoryfile.format(timestamp)
        return os.path.join(self.configdir, filename)

    def _run_binsec_robust_command(self, candidate, directives, controlled, formatted=False):
        self.stats.get_oracle('binsec').calls += 1
        # Normalize/guard assumption lines to avoid generating invalid BINSEC scripts.
        def _append_assumption(expr):
            if expr is None:
                return
            expr = str(expr).strip()
            if not expr:
                return
            if expr.startswith('at ') or (expr.startswith('0x') and ' assume ' in expr):
                norm = self._normalize_directive(expr)
                if norm and ' assume ' in norm and not norm.rstrip().endswith(' assume'):
                    directives.append(norm)
                return
            directives.append('at {} assume {}'.format(self.addr, expr))

        if formatted:
            _append_assumption(candidate)
        else:
            for assump in candidate:
                _append_assumption(assump)
        local_config_file = self._get_local_cfname()
        local_memory_file = self._get_local_mename()
        self.memory.set_controlled(controlled)
        with open(local_memory_file, 'w') as stream:
            self.memory.write(stream)
        memory_rules = []
        with open(local_memory_file, 'r') as stream:
            for line in stream:
                rule = self._normalize_memory_line(line)
                if rule:
                    memory_rules.append(rule)
        script = self._build_script(directives, memory_rules=memory_rules)
        with open(local_config_file, 'w') as stream:
            stream.write(script)
        binsec = os.environ.get('BINSEC', 'binsec')
        command = [binsec, '-sse', '-sse-script', local_config_file, self.binary]
        if self.args.binsec_timeout is not None:
            command += ['-sse-timeout', str(self.args.binsec_timeout)]
        btime = time.time()
        rc, to, out, err = execute_command(command, self.log, timeout=self.args.binsec_timeout)
        atime = time.time()
        if to:
            self.log.warning('command timeouted')
            self.stats.get_oracle('binsec').timeouts += 1
        elif rc != 0:
            self.log.warning('command failed')
            self.stats.get_oracle('binsec').crashes += 1
        else:
            self.stats.get_oracle('binsec').times.append(atime - btime)
        parser = BinsecLogParser(out, self.log, robust=True, translation=self.memory.translator)
        if self.args.binsec_delete_configs:
            os.remove(local_config_file)
            os.remove(local_memory_file)
        return parser

    def _check_ngoal_unreachable(self, candidate):
        directives = [ d for d in self.directives['all'] ]
        directives.extend(self.directives['negative'])
        directives = [
            (d + ' then print model') if d.startswith('reach ') and 'then print model' not in d else d
            for d in directives
        ]
        # Use controlled variables for robust exploration; uncontrolled vars should not
        # be treated as controllable inputs in the memory overlay.
        parser = self._run_binsec_robust_command(candidate, directives, self.var_engine.get_controlled())
        status = parser.status['goal-unreachable'] or len(parser.models) <= 0
        model = parser.models[0]['model'] if len(parser.models) > 0 else None
        model = self._sanitize_model(model)
        if not status and model is None:
            self.log.warning('binsec test returned neither model nor unreachable')
            # TODO: Handle unknown case (such as timeouts)
        if model is not None:
            controlled = self.var_engine.get_controlled()
            if controlled:
                model['*controlled'] = controlled
        return status, model, None

    def _check_dgoal_robust(self, candidate):
        directives = [ d for d in self.directives['all'] ]
        directives.extend(self.directives['positive'])
        directives = [
            (d + ' then print model') if d.startswith('reach ') and 'then print model' not in d else d
            for d in directives
        ]
        parser = self._run_binsec_robust_command(candidate, directives, self.var_engine.get_controlled())
        status = len(parser.models) > 0
        return status, None, None
# --------------------
