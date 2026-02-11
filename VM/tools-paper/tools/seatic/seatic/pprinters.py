# --------------------
import os
import enum
# -------------------
def padding(value, target):
    return ' ' * (target - len(str(value)))
# -------------------
def print_pretty_table(itable, stream, pad=0, aslist=True, bdr='log', use_maxlen=True, split=False, sortkey=None, firstcol=None, withtotal=False):
    old_bdr = GLOBAL_BDR
    set_global_bdr(bdr)

    table = itable if aslist else { k: [v] for k,v in itable.items() }
    if firstcol:
        table[''] = firstcol if aslist else [firstcol]
    keys = list(table.keys())
    keys.sort(key=sortkey)

    total = None
    if withtotal:
        total = dict()
        for k in keys:
            try:
                total[k] = sum(table[k])
            except:
                total[k] = 'NaN'
        if firstcol:
            total[''] = 'Total'

    mlens = { k: max([len(str(s)) for s in [k] + table[k]]) for k in keys }
    if withtotal:
        mlens = { k : max(v, len(str(total[k]))) for k, v in mlens.items() }

    if use_maxlen:
        maxlen = max(mlens.values())
        mlens = { k: maxlen for k in mlens.keys() }
    table_length = sum(mlens.values())+3*len(mlens)+1

    try:
        win_cols, win_lines = os.get_terminal_size()
    except OSError:
        split = False

    if split and table_length > win_cols:
        loc_keys = []
        loc_sum = 0
        first = True
        for k in keys:
            if loc_sum + mlens[k] + 3 + 1 <= win_cols:
                loc_keys.append(k)
                loc_sum += mlens[k] + 3
            else:
                if first:
                    first = False
                else:
                    stream.write(' '*pad)
                print_ptgrid(table, stream, pad, bdr, loc_keys, loc_sum+1, mlens, total)
                loc_keys = [k]
                loc_sum = mlens[k] + 3
                if firstcol:
                    loc_keys = ['', k]
                    loc_sum += mlens[''] + 3
        if loc_keys:
            if not first:
                stream.write(' '*pad)
            print_ptgrid(table, stream, pad, bdr, loc_keys, loc_sum+1, mlens, total)
    else:
        print_ptgrid(table, stream, pad, bdr, keys, table_length, mlens, total)

    set_global_bdr(old_bdr)
# -------------------
BORDERS = {
    'log' : { 'TL': '+', 'TR': '+', 'L': '-', 'M': '|', 'ME': '|', 'ML': '+', 'MR': '+', 'BL': '+', 'BR': '+', 'LTC': '+', 'LC': '+', 'LBC': '+' },
    'tty' : { 'TL': '┌', 'TR': '┐', 'L': '─', 'M': '│', 'ME': '│', 'ML': '├', 'MR': '┤', 'BL': '└', 'BR': '┘', 'LTC': '┬', 'LC': '┼', 'LBC': '┴' },
    'tex' : { 'TL': '', 'TR': '\\hline', 'L': '', 'M': '&', 'ME': '\\\\\\hline', 'ML': '', 'MR': '\\hline', 'BL': '', 'BR': '', 'LTC': '', 'LC': '', 'LBC': '' },
}
TOPHOOKS = {
    'log' : lambda stream, n : None,
    'tty' : lambda stream, n : None,
    'tex' : lambda stream, n : stream.write('\\begin{tabular}{|' + 'r|'*(n+1) + '}\n'),
}
BOTHOOKS = {
    'log' : lambda stream, n : None,
    'tty' : lambda stream, n : None,
    'tex' : lambda stream, n : stream.write('\\end{tabular}\n'),
}
PRINTING_PARADIGMS = BORDERS.keys()
# -------------------
def print_ptgrid(table, stream, pad, bdr, keys, table_length, mlens, total):
    "Format: table[col][line]"
    TOPHOOKS[bdr](stream, len(keys))

    topline = ''.join(('{}{}'.format(BORDERS[bdr]['L']*(mlens[k]+2), BORDERS[bdr]['LTC']) for k in keys))[:-1]
    stream.write('{}{}{}\n{}'.format(BORDERS[bdr]['TL'], topline, BORDERS[bdr]['TR'], ' '*pad))

    for k in keys:
        stream.write('{} {}{} '.format(BORDERS[bdr]['M'], padding(k, mlens[k]), k))
    
    stream.write('{}\n{}'.format(BORDERS[bdr]['ME'], ' '*pad))
    midline = ''.join(('{}{}'.format(BORDERS[bdr]['L']*(mlens[k]+2), BORDERS[bdr]['LC']) for k in keys))[:-1]
    stream.write('{}{}{}\n{}'.format(BORDERS[bdr]['ML'], midline, BORDERS[bdr]['MR'], ' '*pad))

    mline = max((len(l) for l in table.values()))
    for lid in range(mline):
        for k in keys:
            v = table[k][lid] if lid < len(table[k]) else ''
            stream.write('{} {}{} '.format(BORDERS[bdr]['M'], padding(v, mlens[k]), v))
        stream.write('{}\n{}'.format(BORDERS[bdr]['ME'], ' '*pad))

    if total is not None:
        stream.write('{}{}{}\n{}'.format(BORDERS[bdr]['ML'], midline, BORDERS[bdr]['MR'], ' '*pad))
        for k in keys:
            v = total[k]
            stream.write('{} {}{} '.format(BORDERS[bdr]['M'], padding(v, mlens[k]), v))
        stream.write('{}\n{}'.format(BORDERS[bdr]['ME'], ' '*pad))

    botline = ''.join(('{}{}'.format(BORDERS[bdr]['L']*(mlens[k]+2), BORDERS[bdr]['LBC']) for k in keys))[:-1]
    stream.write('{}{}{}\n'.format(BORDERS[bdr]['BL'], botline, BORDERS[bdr]['BR']))

    BOTHOOKS[bdr](stream, len(keys))
# -------------------
GLOBAL_BDR = 'log'
# -------------------
def set_global_bdr(bdr):
    global GLOBAL_BDR
    GLOBAL_BDR = bdr
# -------------------
class PrintStatus(enum.Enum):
    Valid   = 'Y'
    Invalid = 'N'
    Unknown = 'U'
    Timeout = 'T'
    Error   = 'E'

    def __str__(self):
        return STATUSES[GLOBAL_BDR][self]
# -------------------
class PrintStatuses:

    def __init__(self, statuses):
        self.statuses = statuses

    def __str__(self):
        return ' '.join((str(s) for s in self.statuses))
# -------------------
STATUSES = {
    'log' : { PrintStatus.Valid: 'Yes',  PrintStatus.Invalid: 'No',  PrintStatus.Unknown: '?',  PrintStatus.Timeout: 'timeout',  PrintStatus.Error: 'Error', },
    'tty' : { PrintStatus.Valid: '✓',  PrintStatus.Invalid: '✗',  PrintStatus.Unknown: '?',  PrintStatus.Timeout: 'to',  PrintStatus.Error: 'E', },
    'tex' : { PrintStatus.Valid: 'Yes',  PrintStatus.Invalid: 'No',  PrintStatus.Unknown: 'Ukn',  PrintStatus.Timeout: 'To',  PrintStatus.Error: 'Err', },
}
# -------------------
def prettify(v, bdr):
    pass
# -------------------
