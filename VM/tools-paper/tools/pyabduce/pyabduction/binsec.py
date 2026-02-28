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
from .ct_types import LeakSite, OracleResult
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
            'command-failed': False,
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
                lkey, _, lraw = modell.partition(':')
                lkey = lkey.strip()
                lraw = lraw.strip()
                if not lkey or not lraw:
                    continue
                if ';' in lraw and not '(;)' in lraw:
                    # parse registers
                    rname = lkey
                    if rname.startswith('bs_unknown1_for_'):
                        rname = rname.replace('bs_unknown1_for_', '')
                        while rname.startswith('_'):
                            rname = rname[1:]
                    if rname.startswith('undef_AF_1___'):
                        rname = rname.replace('undef_AF_1___', '0x')
                    if '_' in rname:
                        rname = rname.split('_')[0]
                    rcontent = lraw.replace('{', '').replace('}', '').split(';')
                    rvalue, rsize = _normalize_value(rcontent[0]), rcontent[1].strip()
                    rname = _normalize_key(rname)
                    if not rname.startswith('dummy') and not rname.startswith('bs'):
                        result[rname] = rvalue
                    # TODO : store and use rsize?
                    #self.logger.debug('from ["{}"]: @[{}] <- {}'.format(modell, rname, rvalue))
                else:
                    # Ignore trailing ASCII annotation in values, e.g.:
                    # "#x080e3f5b : 3a  (:)" where "(:)" contains a colon.
                    key = _normalize_key(lkey)
                    mm = re.match(r'^(0x[0-9a-fA-F]+|0b[01]+|[0-9a-fA-F]+|-?\d+)\b', lraw)
                    if mm is not None:
                        vtok = mm.group(1).strip()
                    else:
                        parts = lraw.split()
                        if not parts:
                            continue
                        vtok = parts[0].strip()
                    result[key] = _normalize_value(vtok)
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
        self._ct_secret_vars = set()
        self._ct_pivot_var_hints = set()
        self._ct_pivot_addrs = set()
        self._ct_pivot_consts = set()
        dyn_limit = int(getattr(self.args, 'dynamic_constants_per_var', 3))
        # Bitwise-only searches become unstable if too many per-var dynamic
        # constants are injected from counterexamples.
        if getattr(self.args, 'with_bitwise_terms', False) and not getattr(self.args, 'with_arith_terms', False):
            dyn_limit = min(dyn_limit, 1)
        self._max_dyn_consts_per_var = max(1, dyn_limit)
        self._init_vars()
        self._init_varengine()

    def _init_varengine(self):
        self.checkers.var_engine = self

    def _parse_var_addr_size(self, varid):
        if not isinstance(varid, str):
            return None, None
        m = re.match(r'^(0x[0-9a-fA-F]+)(?::([0-9]+))?$', varid)
        if m is None:
            return None, None
        try:
            addr = int(m.group(1), 16)
        except ValueError:
            return None, None
        size = int(m.group(2)) if m.group(2) is not None else 1
        if size <= 0:
            size = 1
        return addr, size

    def _to_int_token(self, token):
        if token is None:
            return None
        sval = str(token).strip()
        if sval == '':
            return None
        try:
            return int(sval, 0)
        except ValueError:
            return None

    def _ct_secret_ranges(self):
        ranges = []
        symbols = getattr(self.checkers, 'symbol_regions', {}) or {}
        for name, data in symbols.items():
            if not isinstance(name, str) or not isinstance(data, tuple) or len(data) != 2:
                continue
            if name.startswith('secret_') or name.startswith('__VERIFIER_nondet_slot'):
                ranges.append(data)
        for raw in getattr(self.args, 'ct_secret', []) or []:
            for token in str(raw).split(','):
                t = token.strip()
                if not t:
                    continue
                if t in symbols:
                    ranges.append(symbols[t])
                    continue
                m = re.match(r'^(0x[0-9a-fA-F]+)(?::([0-9]+))?$', t)
                if m is not None:
                    try:
                        base = int(m.group(1), 16)
                        size = int(m.group(2)) if m.group(2) is not None else 1
                    except ValueError:
                        continue
                    if size > 0:
                        ranges.append((base, size))
        # stable unique
        seen = set()
        out = []
        for base, size in ranges:
            key = (int(base), int(size))
            if key not in seen:
                seen.add(key)
                out.append(key)
        return out

    def _refresh_ct_semantic_hints(self):
        self._ct_secret_vars = set()
        self._ct_pivot_var_hints = set()
        self._ct_pivot_addrs = set()
        self._ct_pivot_consts = set()
        if not getattr(self.args, 'ct_mode', False):
            return

        pivots = getattr(self.checkers, 'ct_explain_pivots', []) or []
        for pivot in pivots:
            if not isinstance(pivot, dict):
                continue
            v = pivot.get('variable')
            if v is not None:
                vtxt = str(v).strip()
                if vtxt:
                    self._ct_pivot_var_hints.add(vtxt)
                    for mm in re.finditer(r'0x[0-9a-fA-F]+', vtxt):
                        try:
                            self._ct_pivot_addrs.add(int(mm.group(0), 16))
                        except ValueError:
                            continue
            cint = self._to_int_token(pivot.get('constant'))
            if cint is not None:
                self._ct_pivot_consts.add(cint & 0xffffffff if cint >= 0 else cint)
                if cint >= 0:
                    # Keep compatibility with current literal source and only
                    # add missing pivot constants as optional candidates.
                    cid = self.checkers.context.declare_const('0x{:x}'.format(cint))
                    self.vars.add(cid)

        sranges = self._ct_secret_ranges()
        if not sranges:
            return
        for vid in self.vars:
            base, size = self._parse_var_addr_size(vid)
            if base is None:
                continue
            for sbase, ssize in sranges:
                if base < sbase + ssize and sbase < base + size:
                    self._ct_secret_vars.add(vid)
                    break

    def _matches_pivot_var(self, varid):
        if not self._ct_pivot_var_hints and not self._ct_pivot_addrs:
            return False
        sval = str(varid)
        if sval in self._ct_pivot_var_hints:
            return True
        for hint in self._ct_pivot_var_hints:
            if hint in sval or sval in hint:
                return True
        base, _ = self._parse_var_addr_size(varid)
        if base is not None and base in self._ct_pivot_addrs:
            return True
        return False

    def _is_pivot_const(self, varid):
        if not self._ct_pivot_consts:
            return False
        if not isinstance(varid, str) or not self.checkers.context.is_const(varid):
            return False
        cstr = self.checkers.context.vars[varid][0].core
        cint = self._to_int_token(cstr)
        if cint is None:
            return False
        norm = (cint & 0xffffffff) if cint >= 0 else cint
        return norm in self._ct_pivot_consts

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
            self._refresh_ct_semantic_hints()
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
        self._refresh_ct_semantic_hints()

    def _update_operators(self):
        # TODO : Use a config file instead
        self.operators.add(minibinsec.Operator.Equal)
        if self.args.with_disequalities:
            self.operators.add(minibinsec.Operator.Distinct)
        if self.args.with_inequalities:
            bitvector_mode = bool(
                getattr(self.args, 'with_bitwise_terms', False)
                or getattr(self.args, 'with_shift_terms', False)
            )
            if bitvector_mode:
                # Bitwise/shift examples are typically lowered to unsigned
                # comparisons (ja/jbe/jb/jae). Keep <u by default.
                self.operators.add(minibinsec.Operator.LowerU)
                if getattr(self.args, 'ct_mode', False):
                    # In CT mode, branch pivots often come from signed tests
                    # (e.g., jle/jg from "if (x > c)"), and keeping only <u
                    # can force over-restrictive policies such as x <u 1.
                    self.operators.add(minibinsec.Operator.Lower)
            else:
                self.operators.add(minibinsec.Operator.Lower)
                self.operators.add(minibinsec.Operator.LowerU)

    def _var_sort_key(self, varid):
        try:
            sz = self.checkers.context.get_size(varid)
        except Exception:
            sz = 0
        is_const = self.checkers.context.is_const(varid)
        if getattr(self.args, 'ct_mode', False):
            if is_const:
                sem = 1 if self._is_pivot_const(varid) else 3
            else:
                if varid in self._ct_secret_vars:
                    sem = 0
                elif self._matches_pivot_var(varid):
                    sem = 1
                else:
                    sem = 2
        else:
            sem = 1
        if is_const:
            return (sem, 2, -sz, str(varid))
        # Prefer wider (word-level) variables first.
        if sz >= 32:
            return (sem, 0, -sz, str(varid))
        return (sem, 1, -sz, str(varid))

    def _normalize_pair_refs(self, v1, v2):
        def _term_size(ref):
            if isinstance(ref, str):
                return self.checkers.context.get_size(ref)
            return ref.bvsize()
        def _is_const_ref(ref):
            return isinstance(ref, str) and self.checkers.context.is_const(ref)
        def _resized_const(const_id, target_size):
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

        s1, s2 = _term_size(v1), _term_size(v2)
        if s1 == s2:
            return v1, v2
        c1, c2 = _is_const_ref(v1), _is_const_ref(v2)
        if c1 and not c2:
            nv1 = _resized_const(v1, s2)
            return (nv1, v2) if nv1 is not None else (None, None)
        if c2 and not c1:
            nv2 = _resized_const(v2, s1)
            return (v1, nv2) if nv2 is not None else (None, None)
        return None, None

    def _safe_binary_literal(self, op, lhs, rhs):
        def _term_size(ref):
            if isinstance(ref, str):
                return self.checkers.context.get_size(ref)
            return ref.bvsize()
        def _is_const_ref(ref):
            return isinstance(ref, str) and self.checkers.context.is_const(ref)

        lhs, rhs = self._normalize_pair_refs(lhs, rhs)
        if lhs is None or rhs is None:
            return None
        if _is_const_ref(lhs) and _is_const_ref(rhs):
            return None
        if _term_size(lhs) != _term_size(rhs):
            return None
        if self.args.no_variables_binop and (not _is_const_ref(lhs)) and (not _is_const_ref(rhs)):
            return None
        literal = self.checkers.context.create_binary_term(op, lhs, rhs)
        if self.ncoreset is not None and literal in self.ncoreset:
            return None
        return literal

    def _generate_human_literals(self, ordered_vars):
        lits = []
        seen = set()
        vars_nonconst = [v for v in ordered_vars if not self.checkers.context.is_const(v)]
        const_ids = [v for v in ordered_vars if self.checkers.context.is_const(v)]
        inequality_ops = [op for op in (minibinsec.Operator.Lower, minibinsec.Operator.LowerU) if op in self.operators]

        def _push(term):
            if term is None:
                return
            key = str(term)
            if key in seen:
                return
            seen.add(key)
            lits.append(term)

        for varid in vars_nonconst:
            for cst in const_ids:
                eq = self._safe_binary_literal(minibinsec.Operator.Equal, varid, cst)
                _push(eq)  # f = c

                for op in inequality_ops:
                    lt = self._safe_binary_literal(op, varid, cst)  # f < c
                    gt = self._safe_binary_literal(op, cst, varid)  # c < f
                    _push(lt)
                    _push(gt)
                    if eq is not None and lt is not None:
                        leq = self.checkers.context.create_multiterm(minibinsec.Operator.Or, [lt, eq])  # f <= c
                        if self.ncoreset is None or leq not in self.ncoreset:
                            _push(leq)
        return lits

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

        def _term_size(ref):
            if isinstance(ref, str):
                return self.checkers.context.get_size(ref)
            return ref.bvsize()

        def _is_const_ref(ref):
            return isinstance(ref, str) and self.checkers.context.is_const(ref)

        def _const_int_value(ref):
            if not _is_const_ref(ref):
                return None
            cstr = self.checkers.context.vars[ref][0].core
            try:
                return int(cstr, 0)
            except ValueError:
                return None

        def _normalize_pair(v1, v2):
            s1, s2 = _term_size(v1), _term_size(v2)
            if s1 == s2:
                return v1, v2
            c1, c2 = _is_const_ref(v1), _is_const_ref(v2)
            if c1 and not c2:
                nv1 = _resized_const(v1, s2)
                return (nv1, v2) if nv1 is not None else (None, None)
            if c2 and not c1:
                nv2 = _resized_const(v2, s1)
                return (v1, nv2) if nv2 is not None else (None, None)
            return None, None

        def _append_literal(op, lhs, rhs, out):
            lhs, rhs = _normalize_pair(lhs, rhs)
            if lhs is None or rhs is None:
                return
            if _is_const_ref(lhs) and _is_const_ref(rhs):
                return
            if _term_size(lhs) != _term_size(rhs):
                return
            if self.args.no_variables_binop and (not _is_const_ref(lhs)) and (not _is_const_ref(rhs)):
                return
            literal = self.checkers.context.create_binary_term(op, lhs, rhs)
            if not literal in self.ncoreset:
                out.append(literal)

        def _generate_arith_terms(var_ids, include_mul=False):
            # Build arithmetic expressions directly in the SMT term graph.
            # This avoids depending on compiler temporaries (e.g., eax).
            limit = max(0, int(getattr(self.args, 'arith_term_limit', 32)))
            if limit == 0:
                return []
            terms = []
            seen = set()
            for var1, var2 in itertools.combinations(var_ids, 2):
                if _term_size(var1) != _term_size(var2):
                    continue
                tadd = self.checkers.context.create_binary_term(minibinsec.Operator.Add, var1, var2)
                kadd = ('+', str(tadd))
                if kadd not in seen:
                    seen.add(kadd)
                    terms.append(tadd)
                    if len(terms) >= limit:
                        break

                tsub = self.checkers.context.create_binary_term(minibinsec.Operator.Sub, var1, var2)
                ksub = ('-', str(tsub))
                if ksub not in seen:
                    seen.add(ksub)
                    terms.append(tsub)
                    if len(terms) >= limit:
                        break

                trsub = self.checkers.context.create_binary_term(minibinsec.Operator.Sub, var2, var1)
                krsub = ('-', str(trsub))
                if krsub not in seen:
                    seen.add(krsub)
                    terms.append(trsub)
                    if len(terms) >= limit:
                        break

                if include_mul:
                    tmul = self.checkers.context.create_binary_term(minibinsec.Operator.Mul, var1, var2)
                    kmul = ('*', str(tmul))
                    if kmul not in seen:
                        seen.add(kmul)
                        terms.append(tmul)
                        if len(terms) >= limit:
                            break
            return terms

        def _generate_bitwise_terms(var_ids, const_ids, include_shifts=False):
            limit = max(0, int(getattr(self.args, 'bitwise_term_limit', 32)))
            if limit == 0:
                return []
            terms = []
            seen = set()

            def _append_term(term, tag):
                key = (tag, str(term))
                if key in seen:
                    return False
                seen.add(key)
                terms.append(term)
                return len(terms) >= limit

            # Prefer small constants for masks/shifts.
            ranked_consts = []
            for cid in const_ids:
                ival = _const_int_value(cid)
                if ival is None:
                    continue
                ranked_consts.append((abs(ival), cid, ival))
            ranked_consts.sort(key=lambda x: x[0])
            const_order = [cid for _, cid, _ in ranked_consts]
            # Prefer meaningful shift amounts (>1) to avoid noisy masks like
            # 0x7fffffff in candidates; keep shift-by-1 only as fallback.
            shift_const_order = [cid for _, cid, ival in ranked_consts if 2 <= ival <= 31]
            if not shift_const_order:
                shift_const_order = [cid for _, cid, ival in ranked_consts if 1 <= ival <= 31]
            if not shift_const_order:
                for fallback in ('0x00000001', '0x00000002', '0x00000004', '0x00000008'):
                    fc = self.checkers.context.declare_const(fallback)
                    self.vars.add(fc)
                    shift_const_order.append(fc)

            if include_shifts:
                # BINSEC assumption parsing is unstable with explicit << / >> in
                # candidate literals. Use shift-inspired mask terms instead.
                #
                # Interleave vars first to avoid consuming the whole term budget
                # on the first symbol only (which harms convergence on
                # multi-variable benchmarks).
                for scst in shift_const_order:
                    sval = _const_int_value(scst)
                    if sval is None or sval <= 0 or sval >= 32:
                        continue
                    low_mask = (0xffffffff >> sval) & 0xffffffff
                    high_mask = (0xffffffff << sval) & 0xffffffff
                    lcid = self.checkers.context.declare_const('0x{:08x}'.format(low_mask))
                    hcid = self.checkers.context.declare_const('0x{:08x}'.format(high_mask))
                    self.vars.add(lcid)
                    self.vars.add(hcid)
                    for var in var_ids:
                        tkeep = self.checkers.context.create_binary_term(minibinsec.Operator.BitAnd, var, lcid)
                        if _append_term(tkeep, 'shiftmask-low'):
                            return terms
                        tlost = self.checkers.context.create_binary_term(minibinsec.Operator.BitAnd, var, hcid)
                        if _append_term(tlost, 'shiftmask-high'):
                            return terms
                return terms

            # Spread unary and mask-based terms across vars before deepening.
            for var in var_ids:
                tnot = self.checkers.context.create_unary_term(minibinsec.Operator.BvNot, var)
                if _append_term(tnot, 'not'):
                    return terms

            for cst in const_order:
                cval = _const_int_value(cst)
                # Skip neutral all-zero/all-one masks; they create many
                # tautological terms and slow down convergence.
                if cval in (0, 0xffffffff):
                    continue
                for var in var_ids:
                    tand = self.checkers.context.create_binary_term(minibinsec.Operator.BitAnd, var, cst)
                    if _append_term(tand, 'andc'):
                        return terms
                    tor = self.checkers.context.create_binary_term(minibinsec.Operator.BitOr, var, cst)
                    if _append_term(tor, 'orc'):
                        return terms

            for var1, var2 in itertools.combinations(var_ids, 2):
                if _term_size(var1) != _term_size(var2):
                    continue
                tand = self.checkers.context.create_binary_term(minibinsec.Operator.BitAnd, var1, var2)
                if _append_term(tand, 'andv'):
                    return terms
                tor = self.checkers.context.create_binary_term(minibinsec.Operator.BitOr, var1, var2)
                if _append_term(tor, 'orv'):
                    return terms

            return terms

        lits = []
        shift_mode = bool(getattr(self.args, 'with_shift_terms', False))
        inequality_ops = {minibinsec.Operator.Lower, minibinsec.Operator.LowerU}
        ordered_vars = sorted(self._reduce_auto(self.vars), key=self._var_sort_key)
        for op in self.operators:
            if shift_mode:
                # In shift mode, build literals only from generated shift
                # terms (handled below), not from all raw var/const pairs.
                continue
            if op not in inequality_ops:
                for var1, var2 in itertools.combinations(ordered_vars, 2):
                    if self.args.core_literals:
                        _append_literal(op, var1, var2, lits)
                    if self.args.separate_bytes:
                        lits.extend(self._generate_byte_literals(op, var1, var2))
                    if self.args.separate_bits:
                        lits.extend(self._generate_bit_literals(op, var1, var2))
            else:
                # In shift mode, avoid raw inequalities on base vars/consts;
                # focus inequalities on generated shift terms instead.
                if shift_mode:
                    continue
                for var1, var2 in itertools.permutations(ordered_vars, 2):
                    if self.args.core_literals:
                        _append_literal(op, var1, var2, lits)
                    # TODO: byte and bit separation for inequalities

        use_arith_terms = bool(
            getattr(self.args, 'with_arith_terms', False)
            or (
                self.args.with_inequalities
                and not getattr(self.args, 'with_bitwise_terms', False)
                and not getattr(self.args, 'with_shift_terms', False)
            )
        )
        if use_arith_terms and self.args.core_literals:
            base_vars = [v for v in ordered_vars if not _is_const_ref(v)]
            use_mul_terms = bool(getattr(self.args, 'with_mul_terms', False))
            arith_terms = _generate_arith_terms(base_vars, include_mul=use_mul_terms)
            if arith_terms:
                self.log.debug('generated {} arithmetic terms'.format(len(arith_terms)))
                for op in self.operators:
                    if op not in inequality_ops:
                        for t in arith_terms:
                            for v in ordered_vars:
                                _append_literal(op, t, v, lits)
                    else:
                        for t in arith_terms:
                            for v in ordered_vars:
                                _append_literal(op, t, v, lits)
                                _append_literal(op, v, t, lits)

        use_bitwise_terms = bool(getattr(self.args, 'with_bitwise_terms', False))
        if use_bitwise_terms and self.args.core_literals:
            base_vars = [v for v in ordered_vars if not _is_const_ref(v)]
            const_ids = [v for v in ordered_vars if _is_const_ref(v)]
            use_shifts = bool(getattr(self.args, 'with_shift_terms', False))
            bitwise_terms = _generate_bitwise_terms(base_vars, const_ids, include_shifts=use_shifts)
            if bitwise_terms:
                self.log.debug('generated {} bitwise terms'.format(len(bitwise_terms)))
                compare_targets = const_ids if use_shifts else ordered_vars
                for op in self.operators:
                    if op not in inequality_ops:
                        for t in bitwise_terms:
                            for v in compare_targets:
                                _append_literal(op, t, v, lits)
                    else:
                        for t in bitwise_terms:
                            for v in compare_targets:
                                _append_literal(op, t, v, lits)
                                _append_literal(op, v, t, lits)
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
        def _maybe_order_literals(lits):
            if not self.args.lit_ordering:
                return lits
            mtable = { lit : (-sum(self.checkers.check_satisfied({lit}, model)[0] for model in self.exset), lit.complexity()) for lit in lits }
            self.log.debug('literals ordering table: {}'.format(mtable))
            return sorted(lits, key=lambda lit: mtable[lit])

        def _emit_combinations(lits, depth_from, depth_to):
            if depth_to < depth_from:
                return
            for depth in range(depth_from, depth_to + 1):
                for candidate in itertools.combinations(lits, depth):
                    yield set(c for c in candidate)
                    if self.restart:
                        return

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

            # Layer 0/1: human-readable atoms first, then short conjunctions.
            ordered_vars = sorted(self._reduce_auto(self.vars), key=self._var_sort_key)
            lits_human = _maybe_order_literals(self._generate_human_literals(ordered_vars))
            self.stats.generation.literals = len(lits_human)
            self.log.debug('layer0 human literals: {}'.format(lits_human))

            short_depth = 2
            if self.args.max_depth is not None:
                short_depth = max(0, min(2, int(self.args.max_depth)))
            for cand in _emit_combinations(lits_human, 1, short_depth):
                yield cand
            if self.restart:
                continue

            # Layer 2: full literal space (arith/bitwise/shift included by
            # existing flags) only when layer 0/1 did not reach any solution.
            if self.stats.solutions > 0:
                self.log.debug('skipping layer2 full terms: layer0/1 already found solutions')
                continue

            lits_full = _maybe_order_literals(self._generate_literals())
            self.stats.generation.literals = len(lits_full)
            self.log.debug('layer2 full literals: {}'.format(lits_full))

            max_depth = self.args.max_depth if self.args.max_depth is not None else len(lits_full)
            max_depth = max(0, int(max_depth))
            for cand in _emit_combinations(lits_full, 1, max_depth):
                yield cand
            if self.restart:
                continue
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
        self.ct_explain = []
        self.ct_explain_pivots = []
        self.symbol_regions = self._load_symbol_regions_map()
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
        raw_regions = []
        for name, (base, size) in (self.symbol_regions or {}).items():
            if not (
                name.startswith('__VERIFIER_nondet_slot')
                or name.startswith('public_')
                or name == '_stub_int_array'
                or re.match(r'^_stub_.*_index$', name)
            ):
                continue
            raw_regions.append((base, size, name))

        if not raw_regions:
            return []

        # When instrumented "public_*" mirrors exist, they are the program
        # variables used by branch predicates. Dropping nondet slot mirrors
        # avoids duplicate symbolic inputs and speeds up convergence.
        has_public = any(name.startswith('public_') for _, _, name in raw_regions)
        regions = []
        for base, size, name in raw_regions:
            if has_public and name.startswith('__VERIFIER_nondet_slot'):
                continue
            regions.append((base, size))
        return regions

    def _load_symbol_regions_map(self):
        regions = {}
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
                or name.startswith('secret_')
                or name == '_stub_int_array'
                or re.match(r'^_stub_.*_index$', name)
            ):
                continue
            base = int(addr_s, 16)
            size = int(size_s, 16)
            if size <= 0:
                continue
            regions[name] = (base, size)
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
        if status is None:
            # BINSEC command failure or unknown; do not classify candidate.
            return False, False, None, None, None, None
        statusr, modelr, rcore = True, None, None
        if status:
            self.stats.get_oracle('binsec-unsat-consistent').calls += 1
            statusr, modelr, rcore = self._check_dgoal_reachable(candidate)
            if statusr is None:
                return False, False, None, None, None, None
        return status, statusr, model, modelr, gcore, rcore

    def check_necessity(self, solutions):
        if getattr(self.args, 'ct_mode', False):
            self.log.debug('necessary condition check (ct mode)')
            if any(len(sol) == 0 for sol in solutions):
                # "true" policy already covers all inputs.
                return True
            constraint = self._format_solution_set(solutions)
            result = self.oracle_ct(constraint, [], formatted=False)
            if result.status == 'UNKNOWN':
                self.log.warning('ct necessity check is unknown; treating as non-necessary')
                return False
            # Necessary when the complement of current solutions is insecure.
            return result.status == 'INSECURE'
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
        if reachable is None:
            self.log.warning('necessity check inconclusive due to BINSEC command failure')
            return False
        return not reachable

    def check_vulnerability(self, candidate, reject, complete=False):
        if getattr(self.args, 'ct_mode', False):
            self.log.debug('vulnerability check (ct mode)')
            result = self.oracle_ct(candidate, reject, complete=complete)
            if result.status == 'INSECURE':
                return True, {}, None
            if result.status == 'UNKNOWN':
                self.log.warning('ct vulnerability check returned unknown')
            return False, None, None
        self.log.debug('vulnerability check')
        status, model, core = self._check_dgoal_reachable_util(candidate, reject, complete)
        if status is None:
            self.log.warning('vulnerability check inconclusive due to BINSEC command failure')
            return False, None, None
        return status, model, core

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
        if parser.status.get('command-failed'):
            return None, None, None
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
        if parser.status.get('command-failed'):
            return None, None, None
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

    def _normalize_ct_status(self, status):
        sval = str(status or '').strip().lower()
        if sval == 'secure':
            return 'SECURE'
        if sval == 'insecure':
            return 'INSECURE'
        return 'UNKNOWN'

    def _normalize_leak_kind(self, kind):
        kval = str(kind or '').strip().lower().replace('-', ' ').replace('_', ' ')
        if 'control' in kval and 'flow' in kval:
            return 'control_flow'
        if 'memory' in kval and 'access' in kval:
            return 'memory_access'
        return 'other'

    def _parse_leak_addr(self, leak):
        if not isinstance(leak, dict):
            return 0
        for key in ('instruction', 'addr'):
            raw = leak.get(key)
            if raw is None:
                continue
            try:
                return int(str(raw), 0)
            except ValueError:
                continue
        return 0

    def _map_leaksites(self, leaks):
        mapped = []
        for leak in leaks or []:
            kind = leak.get('kind') if isinstance(leak, dict) else None
            mapped.append(LeakSite(addr=self._parse_leak_addr(leak), kind=self._normalize_leak_kind(kind)))
        return mapped

    def oracle_ct(self, candidate, reject=None, complete=False, formatted=False):
        if reject is None:
            reject = []
        # Accept a logical "true" baseline shorthand.
        if candidate is True:
            candidate = set()
            formatted = False
        status, leaks, parser = self._check_ct_candidate(candidate, reject, complete=complete, formatted=formatted)
        model = None
        if parser is not None and len(parser.models) > 0:
            model = parser.models[0].get('model')
            model = self._sanitize_model(model)
        raw_log = ''
        if parser is not None:
            chunks = []
            for chunk in parser.logdata:
                chunks.append('[{}:{}] {}'.format(chunk.bswitch, chunk.level, chunk.data))
            raw_log = '\n'.join(chunks)
        return OracleResult(
            status=self._normalize_ct_status(status),
            leaks=self._map_leaksites(leaks),
            raw_log=raw_log,
            model=model if model is not None else {},
        )

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
        result = self.oracle_ct(candidate, [])
        if result.status == 'SECURE':
            return True, True, {}, {}, None, None
        if result.status == 'INSECURE':
            return False, False, {}, None, None, None
        # unknown: non-conclusive
        return False, False, None, None, None, None

    def evaluate_ct_policy(self, candidate):
        # Public helper for final validation/reporting.
        result = self.oracle_ct(candidate, [])
        leaks = [
            {
                'addr': '0x{:08x}'.format(leak.addr),
                'instruction': '0x{:08x}'.format(leak.addr),
                'kind': leak.kind,
            }
            for leak in result.leaks
        ]
        return {
            # Keep lowercase "status" for compatibility with current solver
            # output checks while exposing the normalized state too.
            'status': result.status.lower(),
            'status_norm': result.status,
            'leaks': leaks,
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
        failed = False
        if to:
            self.log.warning('command timeouted')
            self.stats.get_oracle('binsec').timeouts += 1
            failed = True
        elif rc != 0:
            self.log.warning('command failed')
            self.stats.get_oracle('binsec').crashes += 1
            failed = True
            if out:
                outline = [line.strip() for line in out.splitlines() if line.strip()]
                if outline:
                    self.log.warning('binsec error output: {}'.format(' | '.join(outline[:3])))
        else:
            self.stats.get_oracle('binsec').times.append(atime - btime)
        parser = BinsecLogParser(out, self.log)
        parser.status['command-failed'] = failed
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
        if status is None:
            return False, False, None, None, None, None
        statusr, modelr, rcore = True, None, None
        if status:
            self.stats.get_oracle('binsec-unsat-consistent').calls += 1
            statusr, modelr, rcore = self._check_dgoal_reachable(candidate)
            if statusr is None:
                return False, False, None, None, None, None
            if statusr:
                status, modelf, fcore = self._check_dgoal_robust(candidate)
                if status is None:
                    return False, False, None, None, None, None
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
        failed = False
        if to:
            self.log.warning('command timeouted')
            self.stats.get_oracle('binsec').timeouts += 1
            failed = True
        elif rc != 0:
            self.log.warning('command failed')
            self.stats.get_oracle('binsec').crashes += 1
            failed = True
            if out:
                outline = [line.strip() for line in out.splitlines() if line.strip()]
                if outline:
                    self.log.warning('binsec error output: {}'.format(' | '.join(outline[:3])))
        else:
            self.stats.get_oracle('binsec').times.append(atime - btime)
        parser = BinsecLogParser(out, self.log, robust=True, translation=self.memory.translator)
        parser.status['command-failed'] = failed
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
        if parser.status.get('command-failed'):
            return None, None, None
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
        if parser.status.get('command-failed'):
            return None, None, None
        status = len(parser.models) > 0
        return status, None, None
# --------------------
