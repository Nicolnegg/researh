import os
import re
import subprocess
from collections import defaultdict


_JCC_TO_REL = {
    'je': '=',
    'jz': '=',
    'jne': '<>',
    'jnz': '<>',
    'jg': '>s',
    'jnle': '>s',
    'jge': '>=s',
    'jnl': '>=s',
    'jl': '<s',
    'jnge': '<s',
    'jle': '<=s',
    'jng': '<=s',
    'ja': '>u',
    'jnbe': '>u',
    'jae': '>=u',
    'jnb': '>=u',
    'jnc': '>=u',
    'jb': '<u',
    'jnae': '<u',
    'jc': '<u',
    'jbe': '<=u',
    'jna': '<=u',
}

def _relation_rank(rel):
    r = str(rel or '').strip()
    if r in {'<s', '<u', '<=s', '<=u', '>s', '>u', '>=s', '>=u'}:
        return 0
    if r == '=':
        return 1
    if r == '<>':
        return 2
    return 3


def _normalize_operand(op):
    data = op.strip()
    if data.startswith('$'):
        data = data[1:]
    data = data.replace('%', '')
    data = re.sub(r'\s+', '', data)
    return data


def _is_const(op):
    return re.fullmatch(r'(-?0x[0-9a-fA-F]+|-?[0-9]+)', op) is not None


def _parse_objdump_insn_line(line):
    if ':' not in line:
        return None
    left, right = line.split(':', 1)
    addr_s = left.strip()
    if not re.fullmatch(r'[0-9a-fA-F]+', addr_s):
        return None
    fields = [x.strip() for x in right.split('\t') if x.strip()]
    if not fields:
        return None
    text = fields[-1]
    parts = text.split(None, 1)
    if not parts:
        return None
    mnemonic = parts[0].strip().lower()
    operands = parts[1].strip() if len(parts) > 1 else ''
    return {
        'addr': int(addr_s, 16),
        'mnemonic': mnemonic,
        'operands': operands,
        'raw': line.rstrip('\n'),
    }


def _dba_path_from_binary(binary):
    if not binary:
        return None
    stem, _ = os.path.splitext(binary)
    dba = stem + '.dba'
    return dba if os.path.isfile(dba) else None


def _parse_dba_blocks(dba_path):
    if not dba_path or not os.path.isfile(dba_path):
        return {}
    hdr = re.compile(r'^# --\s+0x([0-9a-fA-F]+)\s+[0-9a-fA-F ]+\s+([a-zA-Z0-9]+)\s*(.*)$')
    blocks = {}
    cur = None
    with open(dba_path, 'r') as stream:
        for raw in stream:
            line = raw.rstrip('\n')
            m = hdr.match(line.strip())
            if m is not None:
                addr = int(m.group(1), 16)
                cur = {
                    'addr': addr,
                    'mnemonic': m.group(2).lower(),
                    'operands': m.group(3).strip(),
                    'lines': [],
                }
                blocks[addr] = cur
                continue
            if cur is not None:
                cur['lines'].append(line.strip())
    return blocks


def _strip_dba_sizes(expr):
    # Convert c2bc DBA term style to a compact readable form:
    #   7<32> -> 0x7, eax<32> -> eax
    out = re.sub(r'([0-9]+|0x[0-9a-fA-F]+)<[0-9]+>', r'\1', expr)
    out = re.sub(r'([A-Za-z_][A-Za-z0-9_]*)<[0-9]+>', r'\1', out)
    # Normalize DBA memory style: @[x,<-,4] -> @[x,4]
    out = re.sub(r'@\[(.+?),<-,([0-9]+)\]', r'@[\1,\2]', out)
    out = re.sub(r'\s+', ' ', out).strip()
    # normalize decimal constants to hex for consistency in reports
    def _tohex(m):
        val = int(m.group(1), 10)
        return '0x{:x}'.format(val)
    out = re.sub(r'(?<![A-Za-z0-9_])([0-9]+)(?![A-Za-z0-9_])', _tohex, out)
    # Keep memory-size field decimal for compatibility with mem-token parsers.
    def _mem_size_dec(m):
        inner = m.group(1)
        sz = m.group(2)
        try:
            if sz.lower().startswith('0x'):
                sz = str(int(sz, 16))
        except Exception:
            pass
        return '@[{},{}]'.format(inner, sz)
    out = re.sub(r'@\[(.+?),\s*(0x[0-9a-fA-F]+|[0-9]+)\]', _mem_size_dec, out)
    return out


def _parse_dba_assign(line):
    mm = re.search(r'^\s*[0-9]+:\s*(.+?)\s*:=\s*(.+);\s*$', line)
    if mm is None:
        return None, None
    lhs = _strip_dba_sizes(mm.group(1).strip())
    rhs = _strip_dba_sizes(mm.group(2).strip())
    return lhs, rhs


def _contains_token(expr, token):
    if token.startswith('@['):
        return token in expr
    return re.search(r'(?<![A-Za-z0-9_]){}(?![A-Za-z0-9_])'.format(re.escape(token)), expr) is not None


def _replace_token(expr, token, repl):
    if token.startswith('@['):
        return expr.replace(token, repl)
    return re.sub(
        r'(?<![A-Za-z0-9_]){}(?![A-Za-z0-9_])'.format(re.escape(token)),
        repl,
        expr,
    )


def _sorted_block_addrs(dba_blocks):
    return sorted(dba_blocks.keys())


def _find_prev_assignment(dba_blocks, target, before_addr, max_back_blocks=32, include_current=True):
    addrs = _sorted_block_addrs(dba_blocks)
    if len(addrs) <= 0:
        return None
    try:
        end_idx = addrs.index(before_addr)
    except ValueError:
        end_idx = len(addrs) - 1
    if not include_current:
        end_idx -= 1
    if end_idx < 0:
        return None
    start_idx = max(0, end_idx - max_back_blocks)
    for idx in range(end_idx, start_idx - 1, -1):
        blk = dba_blocks[addrs[idx]]
        for line in reversed(blk.get('lines', [])):
            lhs, rhs = _parse_dba_assign(line)
            if lhs is None:
                continue
            if lhs == target:
                return {
                    'rhs': rhs,
                    'addr': blk['addr'],
                }
    return None


def _expr_tokens_for_resolution(expr):
    tokens = []
    reserved = {
        'lsr', 'lsl', 'ror', 'rol', 'and', 'or', 'xor', 'not',
        'uext', 'sext', 'uext32', 'uext33', 'undef', 'goto',
        'ebp', 'esp', 'zf', 'sf', 'cf', 'of', 'pf', 'af',
    }
    for tok in re.findall(r'\b[A-Za-z_][A-Za-z0-9_]*\b', expr):
        if tok.lower() in reserved:
            continue
        tokens.append(tok)
    # Preserve order, drop duplicates.
    uniq = []
    seen = set()
    for tok in tokens:
        if tok in seen:
            continue
        seen.add(tok)
        uniq.append(tok)
    return uniq


def _resolve_operand_expr(dba_blocks, pivot_addr, operand, max_steps=8):
    cur = _strip_dba_sizes(operand)
    if not dba_blocks:
        return cur
    before_addr = pivot_addr
    visited = set()
    for _ in range(max_steps):
        state = (cur, before_addr)
        if state in visited:
            break
        visited.add(state)
        prev = _find_prev_assignment(dba_blocks, cur, before_addr, include_current=True)
        if prev is not None:
            cur = _strip_dba_sizes(prev['rhs'])
            before_addr = prev['addr']
            continue

        # If the whole expression has no direct assignment, try replacing one
        # informative token (register/memory temp) with its previous value.
        replaced = False
        for tok in _expr_tokens_for_resolution(cur):
            p2 = _find_prev_assignment(dba_blocks, tok, before_addr, include_current=False)
            if p2 is None:
                continue
            rhs2 = _strip_dba_sizes(p2['rhs'])
            cur = _replace_token(cur, tok, '({})'.format(rhs2))
            before_addr = p2['addr']
            replaced = True
            break
        if not replaced:
            break
    return cur


def _rewrite_stack_slots(expr, dba_blocks, pivot_addr):
    text = _strip_dba_sizes(expr)
    slots = re.findall(r'@\[\(ebp\s*[^\]]+\),\s*[0-9]+\]', text)
    seen = set()
    for slot in slots:
        if slot in seen:
            continue
        seen.add(slot)
        prev = _find_prev_assignment(dba_blocks, slot, pivot_addr, include_current=False)
        if prev is None:
            continue
        rhs = _resolve_operand_expr(dba_blocks, prev['addr'], prev['rhs'])
        if rhs is None or rhs == '':
            continue
        text = text.replace(slot, '({})'.format(_strip_dba_sizes(rhs)))
    return _strip_dba_sizes(text)


def _dba_assignment_rhs(block):
    for line in block.get('lines', []):
        mm = re.search(r':=\s*(.+);$', line)
        if mm is not None:
            return mm.group(1).strip()
    return None


def _dba_cmp_operands(block):
    # Typical DBA cmp line:
    # res32<32> := (@[(ebp<32> + -8<32>),<-,4] - 7<32>);
    for line in block.get('lines', []):
        mm = re.search(r':=\s*\((.+)\s-\s(.+)\);\s*$', line)
        if mm is not None:
            left = _strip_dba_sizes(mm.group(1).strip())
            right = _strip_dba_sizes(mm.group(2).strip())
            return left, right
    return None, None


def _dba_predicate_for_branch(dba_blocks, branch_addr, branch_mnemonic, max_back=8):
    if not dba_blocks:
        return None
    rel = _JCC_TO_REL.get(branch_mnemonic)
    if rel is None:
        return None
    addrs = sorted(dba_blocks.keys())
    if branch_addr not in dba_blocks:
        return None
    try:
        bidx = addrs.index(branch_addr)
    except ValueError:
        return None
    for idx in range(bidx - 1, max(-1, bidx - max_back) - 1, -1):
        blk = dba_blocks[addrs[idx]]
        mn = blk['mnemonic']
        if mn.startswith('cmp'):
            left, right = _dba_cmp_operands(blk)
            if left is None or right is None:
                continue
            # Resolve temporary registers to source-level DBA expressions.
            if not _is_const(left):
                left = _resolve_operand_expr(dba_blocks, blk['addr'], left)
                left = _rewrite_stack_slots(left, dba_blocks, blk['addr'])
            if not _is_const(right):
                right = _resolve_operand_expr(dba_blocks, blk['addr'], right)
                right = _rewrite_stack_slots(right, dba_blocks, blk['addr'])
            return {
                'predicate': '({} {} {})'.format(left, rel, right),
                'relation': rel,
                'left': left,
                'right': right,
                'pivot_addr': blk['addr'],
            }
        if mn.startswith('test'):
            rhs = _dba_assignment_rhs(blk)
            if rhs is None:
                continue
            expr = _strip_dba_sizes(rhs)
            expr = _resolve_operand_expr(dba_blocks, blk['addr'], expr) if not _is_const(expr) else expr
            expr = _rewrite_stack_slots(expr, dba_blocks, blk['addr']) if not _is_const(expr) else expr
            if branch_mnemonic not in {'jz', 'je', 'jnz', 'jne'}:
                continue
            trel = '=' if branch_mnemonic in {'jz', 'je'} else '<>'
            return {
                'predicate': '(({}) {} 0x0)'.format(expr, trel),
                'relation': trel,
                'left': expr,
                'right': '0x0',
                'pivot_addr': blk['addr'],
            }
    return None


def _disassemble(binary):
    if not binary or not os.path.isfile(binary):
        return []
    try:
        proc = subprocess.run(
            ['objdump', '-d', binary],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
    except Exception:
        return []
    if proc.returncode != 0:
        return []
    insns = []
    for line in proc.stdout.splitlines():
        parsed = _parse_objdump_insn_line(line)
        if parsed is not None:
            insns.append(parsed)
    return insns


def _mk_cmp_pred(cmp_operands, jcc_mnemonic):
    rel = _JCC_TO_REL.get(jcc_mnemonic)
    if rel is None:
        return None
    ops = [x.strip() for x in cmp_operands.split(',')]
    if len(ops) != 2:
        return None
    left = _normalize_operand(ops[1])
    right = _normalize_operand(ops[0])
    return {
        'predicate': '({} {} {})'.format(left, rel, right),
        'relation': rel,
        'left': left,
        'right': right,
    }


def _mk_test_pred(test_operands, jcc_mnemonic):
    if jcc_mnemonic not in {'jz', 'je', 'jnz', 'jne'}:
        return None
    ops = [x.strip() for x in test_operands.split(',')]
    if len(ops) != 2:
        return None
    left = _normalize_operand(ops[1])
    right = _normalize_operand(ops[0])
    rel = '=' if jcc_mnemonic in {'jz', 'je'} else '<>'
    return {
        'predicate': '(({} & {}) {} 0x0)'.format(left, right, rel),
        'relation': rel,
        'left': left,
        'right': right,
    }


def _find_branch_for_leak(insns, leak_addr, dba_blocks=None, max_back_insn=64, max_cmp_back=8):
    if not insns:
        return None
    leak_idx = None
    for idx, insn in enumerate(insns):
        if insn['addr'] >= leak_addr:
            leak_idx = idx
            break
    if leak_idx is None:
        leak_idx = len(insns) - 1
    start = max(0, leak_idx - max_back_insn)
    jcc_idx = None
    for idx in range(leak_idx, start - 1, -1):
        mn = insns[idx]['mnemonic']
        if mn.startswith('j') and mn in _JCC_TO_REL:
            jcc_idx = idx
            break
    if jcc_idx is None:
        return None
    jcc = insns[jcc_idx]
    dba_pred = _dba_predicate_for_branch(dba_blocks or {}, jcc['addr'], jcc['mnemonic'])
    if dba_pred is not None:
        return {
            'predicate': dba_pred['predicate'],
            'relation': dba_pred['relation'],
            'left': dba_pred['left'],
            'right': dba_pred['right'],
            'leak_addr': leak_addr,
            'branch_addr': jcc['addr'],
            'pivot_addr': dba_pred.get('pivot_addr', jcc['addr']),
            'distance': max(0, leak_idx - jcc_idx),
        }
    pivot = None
    cmp_idx = None
    for idx in range(jcc_idx - 1, max(-1, jcc_idx - max_cmp_back) - 1, -1):
        mn = insns[idx]['mnemonic']
        if mn.startswith('cmp'):
            pivot = _mk_cmp_pred(insns[idx]['operands'], jcc['mnemonic'])
            cmp_idx = idx
            break
        if mn.startswith('test'):
            pivot = _mk_test_pred(insns[idx]['operands'], jcc['mnemonic'])
            cmp_idx = idx
            break
    if pivot is None:
        return None
    return {
        'predicate': pivot['predicate'],
        'relation': pivot['relation'],
        'left': pivot['left'],
        'right': pivot['right'],
        'leak_addr': leak_addr,
        'branch_addr': jcc['addr'],
        'pivot_addr': insns[cmp_idx]['addr'] if cmp_idx is not None else jcc['addr'],
        'distance': max(0, leak_idx - jcc_idx),
    }


def _extract_pivot(entry):
    left = entry.get('left')
    right = entry.get('right')
    if left is None or right is None:
        return {
            'predicate': entry.get('predicate'),
            'relation': entry.get('relation'),
            'variable': None,
            'constant': None,
        }
    var = None
    cst = None
    if _is_const(left) and not _is_const(right):
        cst = left
        var = right
    elif _is_const(right) and not _is_const(left):
        cst = right
        var = left
    elif not _is_const(left):
        var = left
    return {
        'predicate': entry.get('predicate'),
        'relation': entry.get('relation'),
        'variable': var,
        'constant': cst,
    }


def build_ct_explain(binary, leak_sites):
    insns = _disassemble(binary)
    dba_blocks = _parse_dba_blocks(_dba_path_from_binary(binary))
    extracted = []
    for leak in leak_sites or []:
        laddr = getattr(leak, 'addr', None)
        if laddr is None:
            continue
        match = _find_branch_for_leak(insns, int(laddr), dba_blocks=dba_blocks)
        if match is not None:
            extracted.append(match)

    grouped = defaultdict(lambda: {'count': 0, 'best_distance': 10 ** 9, 'entry': None})
    for entry in extracted:
        pred = entry['predicate']
        grouped[pred]['count'] += 1
        if entry['distance'] < grouped[pred]['best_distance']:
            grouped[pred]['best_distance'] = entry['distance']
            grouped[pred]['entry'] = entry

    ordered = sorted(
        grouped.values(),
        key=lambda x: (
            _relation_rank(x['entry'].get('relation')),
            -x['count'],
            x['best_distance'],
            x['entry']['predicate'],
        ),
    )
    q_explain = [item['entry']['predicate'] for item in ordered]
    pivots = [_extract_pivot(item['entry']) for item in ordered]

    return {
        'q_explain': q_explain,
        'pivots': pivots,
        'per_leak': extracted,
        'source': 'dba+objdump-dominant-branch',
    }
