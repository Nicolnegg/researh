# -------------------$
import sys
import re
import copy
import enum
import cvc5
from cvc5 import Kind
# ====================
class Operator(enum.Enum):
    Equal = ('=', 1)
    Distinct = ('<>', 2)
    Lower = ('<s', 1)

    Not = ('!', 1)
    And = ('&', 2)
    Or = ('|', 3)

    def __str__(self):
        return self.value[0]

    @property
    def complexity(self):
        return self.value[1]
# --------------------
# --------------------
OperatorTable = {
    Operator.Equal: Kind.EQUAL,
    Operator.Distinct: Kind.DISTINCT,
    Operator.Lower: Kind.BITVECTOR_SLT,

    Operator.Not: Kind.NOT,
    Operator.And: Kind.AND,
    Operator.Or: Kind.OR,
}
# --------------------
class BVarType(enum.Enum):
    Register = enum.auto()
    MemoryLoc = enum.auto()
    Literal = enum.auto()
# --------------------
_MEMLOC_RE = re.compile(r'^(0x[0-9a-fA-F]+)(?:(?::|/)([0-9]+))?$')

def parse_memloc(data: str) -> tuple[str, int]:
    """
    Parse a memory location spec used in the inference language.

    Supported:
      - "0xADDR"   -> (0xADDR, 1) byte
      - "0xADDR:4" -> (0xADDR, 4) bytes
      - "0xADDR/4" -> (0xADDR, 4) bytes
    """
    m = _MEMLOC_RE.match(data)
    if not m:
        raise ValueError(f"invalid memloc spec: {data!r}")
    addr = m.group(1)
    nbytes = int(m.group(2) or "1", 10)
    if nbytes <= 0:
        raise ValueError(f"invalid memloc size: {data!r}")
    return addr, nbytes

def detect_bvar_type(data):
    if data.startswith('0x'):
        return BVarType.MemoryLoc
    return BVarType.Register
# --------------------
class BFormulaCore:

    def __str__(self):
        raise NotImplementedError(self)

    def __repr__(self):
        return self.__str__()
    
    def bvsize(self):
        raise NotImplementedError(self)

    def complexity(self):
        raise NotImplementedError(self)

    def formula_data(self):
        return str(self), self.bvsize()
# --------------------
class BVar(BFormulaCore):

    def __init__(self, core, forcetype=None):
        self.core = core
        self.type = detect_bvar_type(core) if forcetype is None else forcetype
        self.size = self._compute_size()

    def bvsize(self):
        return self.size

    def complexity(self):
        return 0

    def _compute_size(self):
        if self.type == BVarType.MemoryLoc:
            _, nbytes = parse_memloc(self.core)
            return 8 * nbytes
        if self.type == BVarType.Register:
            return 32
        if self.type == BVarType.Literal:
            return 4*len(self.core.replace('0x', '')) if self.core.startswith('0x') else len(self.core.replace('0b', ''))
        raise NotImplementedError((self, self.type))

    def __str__(self):
        if self.type == BVarType.MemoryLoc:
            addr, nbytes = parse_memloc(self.core)
            return '@[{},{}]'.format(addr, nbytes)
        if self.type == BVarType.Register:
            return '{}<32>'.format(self.core)
        if self.type == BVarType.Literal:
            return self.core
        raise NotImplementedError((self, self.type))
# --------------------
class BVarByte(BFormulaCore):

    def __init__(self, var, idx):
        self.var = var
        self.idx = idx
        self.type = var.type
        self.size = 8

    def bvsize(self):
        return self.size

    def complexity(self):
        return self.var.complexity() + 1

    def __str__(self):
        return '({}{{{},{}}})'.format(self.var, self.idx, self.idx+7)
# --------------------
class BVarBit(BFormulaCore):

    def __init__(self, var, idx):
        self.var = var
        self.idx = idx
        self.type = var.type
        self.size = 1

    def bvsize(self):
        return self.size

    def complexity(self):
        return self.var.complexity() + 1

    def __str__(self):
        return f'({self.var}{{{self.idx},{self.idx}}})'
# --------------------
class BUnaryTerm(BFormulaCore):

    def __init__(self, op, var, smt_term):
        self.op = op
        self.var = var
        self.smt_term = smt_term
        self._str_cache = None

    def bvsize(self):
        return self.var.bvsize()

    def complexity(self):
        return self.var.complexity() + self.op.complexity

    def _compute_str(self):
        self._str_cache = '{}({})'.format(self.op, self.var)

    def __str__(self):
        if self._str_cache is None:
            self._compute_str()
        return self._str_cache
# --------------------
class BBinaryTerm(BFormulaCore):

    def __init__(self, op, var1, var2, smt_term):
        self.op = op
        self.var1 = var1
        self.var2 = var2
        self.smt_term = smt_term
        self._str_cache = None
        self._siz_cache = None
        self._cpl_cache = None

    def _compute_str(self):
        sz1, sz2 = self.var1.bvsize(), self.var2.bvsize()
        if sz1 > sz2:
            vart, szt = self.var1, sz1
            self.var1, sz1 = self.var2, sz2
            self.var2, sz2 = vart, szt
        dpad = ''
        if sz1 != sz2:
            dsiz = sz2 - sz1
            if dsiz % 4 == 0:
                dpad = '0x{}::'.format('0'*int(dsiz/4))
            else:
                dpad = '0b{}::'.format('0'*dsiz)
        self._str_cache = '({}{} {} {})'.format(dpad, self.var1, self.op, self.var2)

    def bvsize(self):
        if self._siz_cache is None:
            self._siz_cache = max(self.var1.bvsize(), self.var2.bvsize())
        return self._siz_cache

    def complexity(self):
        if self._cpl_cache is None:
            self._cpl_cache = self.var1.complexity() + self.var2.complexity() + self.op.complexity
        return self._cpl_cache

    def __str__(self):
        if self._str_cache is None:
            self._compute_str()
        return self._str_cache
# --------------------
class BMultiTerm(BFormulaCore):

    def __init__(self, op, terms, smt_term):
        self.op = op
        self.terms = terms
        self.smt_term = smt_term
        self._str_cache = None
        self._cpl_cache = None

    def bvsize(self):
        return 0 # TODO: Handle for non logical operators

    def complexity(self):
        if self._cpl_cache is None:
            self._cpl_cache = sum((t.complexity() for t in self.terms)) + self.op.complexity
        return self._cpl_cache

    def _compute_str(self):
        self._str_cache = ' {} '.format(self.op).join(('{}'.format(term) for term in self.terms))

    def __str__(self):
        if self._str_cache is None:
            self._compute_str()
        return self._str_cache
# --------------------
class Context:

    def __init__(self, logger):
        self.vars = dict()
        self._tcache = dict()
        self.solver = cvc5.Solver()
        self.solver.setOption('produce-models', 'true')
        self.solver.setLogic('ALL')
        self._const_header = '*const:'
        self._byte_header = '*byte:'
        self._bit_header ='*bit:'
        self.bvsorts = dict()
        self.log = logger

    def _constid(self, val):
        return '{}{}'.format(self._const_header, val)

    def _byteid(self, var, idx):
        return '{}:{}:{}'.format(self._byte_header, idx, var)

    def _bitid(self, var, idx):
        return '{}:{}:{}'.format(self._bit_header, idx, var)

    def is_const(self, var):
        return var.startswith(self._const_header)

    def is_byte_restriction(self, var):
        return var.startswith(self._byte_header)

    def is_bit_restriction(self, var):
        return var.startswith(self._bit_header)

    def get_type(self, var):
        return self.vars[var][0].type

    def get_size(self, var):
        return self.vars[var][0].size

    def declare_var(self, vstr):
        if not vstr in self.vars:
            bvar = self.build_binsec_var(vstr)
            svar = self.build_smt_var(vstr, bvar.bvsize())
            self.vars[vstr] = (bvar, svar)
        return vstr

    def declare_const(self, cstr):
        cid = self._constid(cstr)
        if not cid in self.vars:
            bvar = BVar(cstr, forcetype=BVarType.Literal)
            svar = self.solver.mkBitVector(bvar.bvsize(), int(cstr, 16))
            self.vars[cid] = (bvar, svar)
        return cid

    def create_bytes(self, vstr):
        vbytes = []
        for byteidx in range(0, self.get_size(vstr), 8):
            vbytes.append(self.declare_byte(vstr, byteidx))
        return vbytes

    def declare_byte(self, vstr, idx):
        bid = self._byteid(vstr, idx)
        if not bid in self.vars:
            var, smtvar = self.vars[vstr]
            bvar = BVarByte(var, idx)
            extop = self.solver.mkOp(Kind.BITVECTOR_EXTRACT, idx+7, idx)
            svar = self.solver.mkTerm(extop, smtvar)
            self.vars[bid] = (bvar, svar)
        return bid

    def create_bits(self, vstr):
        vbits = []
        for bitidx in range(0, self.get_size(vstr)):
            vbits.append(self.declare_bit(vstr, bitidx))
        return vbits

    def declare_bit(self, vstr, idx):
        bid = self._bitid(vstr, idx)
        if not bid in self.vars:
            var, smtvar = self.vars[vstr]
            bvar = BVarBit(var, idx)
            extop = self.solver.mkOp(Kind.BITVECTOR_EXTRACT, idx, idx)
            svar = self.solver.mkTerm(extop, smtvar)
            self.vars[bid] = (bvar, svar)
        return bid

    def create_var_assignment(self, operator, varid, val):
        valid = self._constid(val)
        tkey = ('va', operator, varid, valid)
        if not tkey in self._tcache:
            self.declare_var(varid)
            var = self.vars[varid]
            valr = BVar(val, forcetype=BVarType.Literal)
            dsize = valr.bvsize() - var[0].bvsize()
            #self.log.debug('create smt assign {}[{}] = {}[{}]'.format(var, var[0].bvsize(), valr, valr.bvsize()))
            if dsize >= 0:
                self._tcache[tkey] =  BBinaryTerm(operator, var[0], valr, self._build_smt_binary_term
                                                    (operator, var[1], self.solver.mkBitVector(valr.bvsize(), int(val, 16)), dsize))
            else:
                self._tcache[tkey] =  BBinaryTerm(operator, valr, var[0], self._build_smt_binary_term
                                                    (operator, self.solver.mkBitVector(valr.bvsize(), int(val, 16)), var[1], -dsize))
        return self._tcache[tkey]

    def build_binsec_var(self, vstr):
        return BVar(vstr)

    def build_smt_var(self, vstr, size):
        if not size in self.bvsorts:
            self.bvsorts[size] = self.solver.mkBitVectorSort(size)
        if vstr.startswith('0x'):
            varname = 'mem_{}'.format(vstr.replace(':', '_').replace('/', '_'))
        else:
            varname = vstr
        return self.solver.mkConst(self.bvsorts[size], varname)

    def create_binary_term(self, operator, id1, id2):
        tkey = ('bt', operator, id1, id2)
        if not tkey in self._tcache:
            var1, var2 = self.vars[id1], self.vars[id2]
            if var1[0].bvsize() > var2[0].bvsize():
                vart = var1
                var1, var2 = var2, vart
            self._tcache[tkey] = BBinaryTerm(operator, var1[0], var2[0],
                                             self._build_smt_binary_term(operator, var1[1], var2[1], var2[0].bvsize() - var1[0].bvsize()))
        return self._tcache[tkey]

    def create_negation(self, terms, iterable=True):
        # TODO: Use term cache
        if not iterable:
            terms = set(terms)
        return BUnaryTerm(Operator.Not, BMultiTerm(Operator.And, terms, 'not-computed'), self._build_smt_set_negation(terms))

    def create_multiterm(self, operator, terms, iterable=True):
        # TODO: use term cache
        if not iterable:
            terms = set(terms)
        return BMultiTerm(operator, terms, self._build_smt_multiterm(operator, terms))

    def _build_smt_binary_term(self, operator, var1, var2, dsize):
        if dsize > 0:
            extop = self.solver.mkOp(Kind.BITVECTOR_ZERO_EXTEND, dsize)
            var1 = self.solver.mkTerm(extop, var1)
        return self.solver.mkTerm(OperatorTable[operator], var1, var2)

    def _build_smt_set_negation(self, terms):
        return self.solver.mkTerm(Kind.NOT, self._build_smt_multiterm(Operator.And, terms))

    def _build_smt_multiterm(self, operator, elems):
        term = None
        for elem in elems:
            if term is None:
                term = elem.smt_term
            else:
                term = self.solver.mkTerm(OperatorTable[operator], term, elem.smt_term)
        return term
# --------------------
def check_sat_core(asserts, assigns, solver):
    solver.push()
    for asn in assigns:
        solver.assertFormula(asn)
    solver.push()
    for ass in asserts:
        solver.assertFormula(ass.smt_term)
    res = solver.checkSat()
    solver.pop()
    solver.pop()
    return res
# --------------------
def check_sat(asserts, context):
    return check_sat_core(asserts, dict(), context.solver).isSat()
# --------------------
def check_sat_model(asserts, model, context):
    assigns = []
    for var, (_, smtvar) in context.vars.items():
        if context.is_const(var) or context.is_byte_restriction(var) or context.is_bit_restriction(var):
            continue
        if var in model:
            bass = context.create_var_assignment(Operator.Equal, var, model[var])
            assigns.append(bass.smt_term)
        elif '*controlled' in model and not var in model['*controlled']:
            pass
        elif 'default' in model:
            bass = context.create_var_assignment(Operator.Equal, var, model['default'])
            assigns.append(bass.smt_term)
        else:
            #raise Exception('AUTO ERROR')
            pass #TODO: ERROR (?)
    return check_sat_core(asserts, assigns, context.solver).isSat()
# --------------------
def check_consequence(implicant, implicate, context):
    asserts = [ f for f in implicant ]
    asserts.append(context.create_negation(implicate))
    return check_sat_core(asserts, dict(), context.solver).isUnsat()
# ====================
# --------------------
