# --------------------
import os.path
import time
import enum
import copy
import pulseutils.strings
from .core import Task
from . import utils
from . import pprinters as pp
# --------------------
def sorting_resolved_addr(s):
    if isinstance(s, str) and '+' in s:
        parts = s.split('+')
        parts[1] = '0x{:#010x}'.format(int(parts[1], 16))
        return '+'.join(parts)
    return s
# --------------------
class VStatus(enum.Enum):
    Vuln    = 'V'
    NoVuln  = 'N'
    Unknown = 'U'
    Timeout = 'T'
    Error   = 'E'

    def __str__(self):
        return VSTATUSES[self]
# ----------
VSTATUSES = { VStatus.Vuln: 'vuln', VStatus.NoVuln: 'not vuln', VStatus.Unknown: 'unkn', VStatus.Timeout: 'to', VStatus.Error: 'crash' }
# --------------------
class ExportResultsTask(Task):

    def __init__(self, ctx, logger, sourcekey=''):
        super().__init__(logger)
        self.ctx = ctx
        self.sourcekey = sourcekey

    def _preprocess(self):
        logdir = self.ctx['target.result-svg']
        if logdir and not os.path.isdir(logdir):
            os.makedirs(logdir)
        self.ctx.expand_models()

    def _execute(self):
        logfile = self.ctx['target.result']
        self.log.info('dumping results to {}'.format(logfile))
        with open(logfile, 'w') as stream:
            self._print_core_rtable(stream)
            self._print_compact_rtable(stream)
        if self.ctx['opt.plots']:
            self.log.warning('local results plots have been deimplemented')
            pass # TODO: redo plots

    def _print_core_rtable(self, stream):
        sortkey = lambda m : ((lambda i : i if i is not None else (-1,))(self.ctx.mutants[m]['skip-locs']) if 'skip-locs' in self.ctx.mutants[m] else (-1,))
        elements = [
                ('mutant', lambda m, md: os.path.basename(m), None),
                ('flocs', lambda m, md: ', '.join(('0x{:x}'.format(faddr) for faddr in md['skip-locs'])), None),
                ('constraint', lambda m, md: self.format_constraint(m, md['abducer']['constraints']) if 'abducer' in md else '', None),
                #('fault insts', lambda m, md: ', '.join((inst[0] for inst in md['skip-insts'])), None),
                ('dtest (Abd-O)', lambda m, md: self.get_vseverity(m, 'abduction'), None),
                ('dtest (Abd-P)', lambda m, md: self.get_pseverity(m, 'abduction'), None),
                ('dtest (SE)', lambda m, md: self.get_vstatus_str(m, 'binsec'), None),
                ('dtest (RSE)', lambda m, md: self.get_vstatus_str(m, 'robust'), None),
                ('dtest (Sim)', lambda m, md: self.get_vstatus_str(m, 'simu'), None),
                ('dtest (Sim*)', lambda m, md: self.get_vseverity(m, 'vsimu'), None),
                ('time (SE)', lambda m, md: md['binsec']['time'] if 'binsec' in md else '', None),
                ('time (RSE)', lambda m, md: md['binsec-robust']['time'] if 'binsec-robust' in md else '', None),
        ]
        table = self.get_table(elements, sortkey)
        table.pop(self.sourcekey)
        firstcol = table.pop('mutant')
        pp.print_pretty_table(table, stream, bdr=self.ctx['opt.rpp-bdr'], firstcol=firstcol, use_maxlen=False, split=True)

    def _print_compact_rtable(self, stream):
        elements = [
                ('+ binsec', lambda m, md: self.get_merged_vstatus(m, 'binsec') == VStatus.Vuln, None),
                ('+ robust', lambda m, md: self.get_merged_vstatus(m, 'robust') == VStatus.Vuln, None),
                ('+ abduct', lambda m, md: self.get_merged_vstatus(m, 'abduction') == VStatus.Vuln, None),
                ('+ simu', lambda m, md: self.get_merged_vstatus(m, 'simu') == VStatus.Vuln, None),
                ('+ vsimu', lambda m, md: self.get_merged_vstatus(m, 'vsimu') == VStatus.Vuln, None),

                ('? binsec', lambda m, md: self.get_merged_vstatus(m, 'binsec') == VStatus.Unknown, None),
                ('? robust', lambda m, md: self.get_merged_vstatus(m, 'robust') == VStatus.Unknown, None),
                ('? abduct', lambda m, md: self.get_merged_vstatus(m, 'abduction') == VStatus.Unknown, None),
                ('? simu', lambda m, md: self.get_merged_vstatus(m, 'simu') == VStatus.Unknown, None),
                ('? vsimu', lambda m, md: self.get_merged_vstatus(m, 'vsimu') == VStatus.Unknown, None),

                ('t binsec', lambda m, md: md['binsec']['time'] if 'binsec' in md else 0, None),
                ('t robust', lambda m, md: md['binsec-robust']['time'] if 'binsec-robust' in md else 0, None),
                ('t abduct', lambda m, md: md['abducer']['time'] if 'abducer' in md else 0, None),
                ('t simu', lambda m, md: md['simulation']['time'] if 'simulation' in md else 0, None),
                ('t vsimu', lambda m, md: md['vsimulation']['time'] if 'vsimulation' in md else 0, None),
        ]
        table = self.get_table(elements)
        categories = [
                (lambda m: True,
                 { k : sum for k in (e[0] for e in elements) },
                 { k : None for k in (e[0] for e in elements) }),
        ]
        atable = self.aggregate_table(table, categories)
        firstcol = ['total']
        pp.print_pretty_table(atable, stream, bdr=self.ctx['opt.rpp-bdr'], firstcol=firstcol, use_maxlen=False, split=True)

    def get_table(self, elements, sortkey=None):
        table = { key : [] for key, _, _ in elements }
        table[self.sourcekey] = []
        for mutant in sorted(self.ctx.mutants.keys(), key=sortkey):
            table[self.sourcekey].append(mutant)
            for key, kgetter, kformatter in elements:
                pval = kgetter(mutant, self.ctx.mutants[mutant])
                table[key].append(kformatter(pval) if kformatter is not None else pval)
        return table

    def aggregate_table(self, table, categories):
        atable = { key : [] for key in table if key != self.sourcekey }
        for ownership, aggregators, formatters in categories:
            for key, vlist in table.items():
                if key != self.sourcekey:
                    mlist = [ m for m in table[self.sourcekey] if ownership(m) ]
                    aggregator = aggregators[key]
                    avalue = aggregator([ vlist[i] for i in (table[self.sourcekey].index(m) for m in mlist)])
                    formatter = formatters[key]
                    atable[key].append(formatter(avalue) if formatter is not None else avalue)
        return atable

    def format_constraint(self, mutant, clist):
        if VStatus.Error in self._get_abduction_vstatus(mutant):
            return 'crash'
        rlist = []
        for constraint in clist:
            if len(constraint) == 0:
                rlist.append('any solution')
            else:
                rlist.append(' & '.join((self._extend_literal(mutant, l) for l in constraint)))
        return '  ;  '.join(rlist) if clist else 'no solution'

    def _extend_literal(self, mutant, lit):
        lit = self._deregistrify(lit)
        operator = self._extract_operator(lit)
        splits = [s.strip() for s in lit.split(operator)]
        rsplits = []
        for s in splits:
            if s.startswith('@'):
                rsplits.append(self.ctx.resolve_addr(mutant, s, unpack=True, repack=True))
            elif '::' in s:
                rsplits.append(self._extend_concat(mutant, s))
            else:
                rsplits.append(s)
        return '({})'.format(' {} '.format(operator).join(rsplits))

    def _extend_concat(self, mutant, lit):
        splits = lit.split('::')
        splits = [ self.ctx.resolve_addr(mutant, s, unpack=True, repack=True) if s.startswith('@') else s for s in splits ]
        return '::'.join(splits)

    def _extract_operator(self, lit):
        for op in ('=', '<>'):
            if op in lit:
                return op

    def _deregistrify(self, lit):
        if not '&' in lit:
            if lit.startswith('('):
                return pulseutils.strings.unparen(lit)
            return lit
        return pulseutils.strings.unparen(lit.split('&')[0].strip())

    def get_corrected_abducer_time(self, mutant):
        rst = self.get_merged_vstatus(mutant, 'robust')
        rtime = self.ctx.mutants[mutant]['binsec-robust']['time'] if 'binsec-robust' in self.ctx.mutants[mutant] else 0
        atime = self.ctx.mutants[mutant]['abducer']['time'] if 'abducer' in self.ctx.mutants[mutant] else 0
        return rtime if rst == VStatus.Vuln else atime

    def get_vstatus(self, mutant, tool):
        getter = getattr(self, '_get_{}_vstatus'.format(tool))
        return getter(mutant)

    def get_vstatus_str(self, mutant, tool):
        statuses = self.get_vstatus(mutant, tool)
        return ', '.join(str(s) for s in statuses)

    def get_merged_vstatus(self, mutant, tool):
        statuses = self.get_vstatus(mutant, tool)
        if VStatus.Error in statuses:
            return VStatus.Unknown
        if VStatus.Vuln in statuses:
            return VStatus.Vuln
        if VStatus.NoVuln in statuses:
            return VStatus.NoVuln
        if tool in ('robust', 'abduction') and len(statuses) == 0:
            # Non-evaluated cases
            return VStatus.NoVuln
        return VStatus.Unknown

    def get_vseverity(self, mutant, tool):
        getter = getattr(self, '_get_{}_vseverity'.format(tool))
        return getter(mutant)

    def get_pseverity(self, mutant, tool):
        getter = getattr(self, '_get_{}_pseverity'.format(tool))
        return getter(mutant)

    def _get_binsec_vstatus(self, mutant):
        status = []
        if 'binsec' in self.ctx.mutants[mutant]:
            if self.ctx.is_vulnerable(mutant):
                status.append(VStatus.Vuln)
            elif not self.ctx.mutants[mutant]['binsec']['timeout'] and self.ctx.mutants[mutant]['binsec']['returncode'] == 0:
                status.append(VStatus.NoVuln)
            else:
                status.append(VStatus.Unknown)
            if self.ctx.mutants[mutant]['binsec']['timeout']:
                status.append(VStatus.Timeout)
            elif self.ctx.mutants[mutant]['binsec']['returncode'] != 0:
                status.append(VStatus.Error)
        return status

    def _get_robust_vstatus(self, mutant):
        status = []
        if self.get_merged_vstatus(mutant, 'binsec') == VStatus.Unknown:
            status.append(VStatus.Unknown)
            return status
        if 'binsec-robust' in self.ctx.mutants[mutant]:
            if self.ctx.mutants[mutant]['binsec-robust']['status']['goal-unreachable']:
                status.append(VStatus.NoVuln)
            elif self.ctx.mutants[mutant]['binsec-robust']['vulnerable']:
                status.append(VStatus.Vuln)
            else:
                status.append(VStatus.Unknown)
            if self.ctx.mutants[mutant]['binsec-robust']['timeout']:
                status.append(VStatus.Timeout)
            elif self.ctx.mutants[mutant]['binsec-robust']['returncode'] != 0:
                status.append(VStatus.Error)
        return status

    def _get_abduction_vstatus(self, mutant):
        status = []
        if 'abducer' in self.ctx.mutants[mutant]:
            if len(self.ctx.mutants[mutant]['abducer']['constraints']) > 0:
                status.append(VStatus.Vuln)
            elif self.ctx.mutants[mutant]['abducer']['timeout']:
                status.append(VStatus.Timeout)
                status.append(VStatus.Unknown)
            elif self.ctx.mutants[mutant]['abducer']['returncode'] != 0:
                status.append(VStatus.Error)
                status.append(VStatus.Unknown)
            else:
                status.append(VStatus.NoVuln)
        return status

    def _get_abduction_necessary_vstatus(self, mutant):
        status = []
        if 'abducer' in self.ctx.mutants[mutant]:
            if len(self.ctx.mutants[mutant]['abducer']['necessary']) > 0:
                status.append(VStatus.Vuln)
            elif 'exact' in self.ctx.mutants[mutant]['abducer'] and self.ctx.mutants[mutant]['abducer']['exact']:
                status.append(VStatus.Vuln)
            elif self.ctx.mutants[mutant]['abducer']['timeout']:
                status.append(VStatus.Timeout)
                status.append(VStatus.Unknown)
            elif self.ctx.mutants[mutant]['abducer']['returncode'] != 0:
                status.append(VStatus.Error)
                status.append(VStatus.Unknown)
            else:
                status.append(VStatus.NoVuln)
        return status

    def _get_abduction_nas_vstatus(self, mutant):
        status = self._get_abduction_vstatus(mutant)
        if VStatus.Vuln in status:
            abddata = self.ctx.mutants[mutant]['abducer']
            if 'exact' in abddata:
                status = [ VStatus.Vuln if abddata['exact'] else VStatus.NoVuln ]
            else:
                status = [ VStatus.Unknown ]
        return status

    def _get_abduction_registers_vstatus(self, mutant):
        status = self._get_abduction_vstatus(mutant)
        if VStatus.Vuln in status:
            abddata = self.ctx.mutants[mutant]['abducer']
            for constraint in abddata['constraints']:
                if self._contains_register(constraint):
                    return [ VStatus.Vuln ]
            return [ VStatus.NoVuln ]
        return status

    def _get_abduction_constants_vstatus(self, mutant):
        status = self._get_abduction_vstatus(mutant)
        if VStatus.Vuln in status:
            abddata = self.ctx.mutants[mutant]['abducer']
            for constraint in abddata['constraints']:
                if self._contains_constant(constraint):
                    return [ VStatus.Vuln ]
            return [ VStatus.NoVuln ]
        return status

    def _contains_register(self, constraint):
        for lit in constraint:
            # TODO: Match things correctly
            if '<32>' in lit:
                return True
        return False

    def _contains_constant(self, constraint):
        for lit in constraint:
            # TODO: Match things correctly
            litr = lit if not '&' in lit else lit.split('&')[0].strip()
            litp = litr.split('=' if '=' in litr else '<>')
            litp = [ p.strip() for p in litp ]
            for p in litp:
                if p.startswith('0x'):
                    return True
        return False

    def _get_simu_vstatus(self, mutant):
        status = []
        if 'simulation' in self.ctx.mutants[mutant]:
            if self.ctx.mutants[mutant]['simulation']['data']['result'] is None:
                status.append(VStatus.Unknown)
            elif self.ctx.mutants[mutant]['simulation']['data']['result']:
                status.append(VStatus.Vuln)
            else:
                status.append(VStatus.NoVuln)
            if self.ctx.mutants[mutant]['simulation']['data']['crash']:
                status.append(VStatus.Error)
            if self.ctx.mutants[mutant]['simulation']['data']['timeout']:
                status.append(VStatus.Timeout)
        return status

    def _get_vsimu_vstatus(self, mutant):
        status = []
        if 'vsimulation' in self.ctx.mutants[mutant]:
            if self.ctx.mutants[mutant]['vsimulation']['auto-timeout']:
                status.append(VStatus.Timeout)
                status.append(VStatus.Unknown)
            elif self.ctx.mutants[mutant]['vsimulation']['returncode'] != 0:
                status.append(VStatus.Error)
                status.append(VStatus.Unknown)
            elif 'matches' in self.ctx.mutants[mutant]['vsimulation']:
                if self.ctx.mutants[mutant]['vsimulation']['matches']['vulnerabilities'] > 0:
                    status.append(VStatus.Vuln)
                elif (not self.ctx.mutants[mutant]['vsimulation']['timeout'] and
                      self.ctx.mutants[mutant]['vsimulation']['returncode'] == 0):
                    status.append(VStatus.NoVuln)
            if self.ctx.mutants[mutant]['vsimulation']['timeout']:
                status.append(VStatus.Timeout)
                status.append(VStatus.Unknown)
        return status

    def _get_binsec_vseverity(self, mutant):
        status = self.get_merged_vstatus(mutant, 'binsec')
        return { VStatus.Vuln: 1, VStatus.NoVuln: 0, VStatus.Unknown: -1 }[status]

    def _get_robust_vseverity(self, mutant):
        status = self.get_merged_vstatus(mutant, 'robust')
        # TODO: compute correct robust vseverity
        return { VStatus.Vuln: 99990000, VStatus.NoVuln: 0, VStatus.Unknown: -1 }[status]

    def _get_abduction_vseverity(self, mutant):
        if 'severity-computation' in self.ctx.mutants[mutant]:
            data = self.ctx.mutants[mutant]['severity-computation']
            if 'value' in data:
                return data['value']
        if 'abducer' in self.ctx.mutants[mutant]:
            return -2
        bstatus = self.get_merged_vstatus(mutant, 'binsec')
        if bstatus == VStatus.NoVuln:
            return 0
        return -1

    def _get_abduction_pseverity(self, mutant):
        if 'severity-computation' in self.ctx.mutants[mutant]:
            data = self.ctx.mutants[mutant]['severity-computation']
            if 'pessimistic' in data:
                return data['pessimistic']
        return self._get_abduction_vseverity(mutant)

    def _get_simu_vseverity(self, mutant):
        status = self.get_merged_vstatus(mutant, 'simu')
        return { VStatus.Vuln: 1, VStatus.NoVuln: 0, VStatus.Unknown: -1 }[status]

    def _get_vsimu_vseverity(self, mutant):
        if 'vsimulation' in self.ctx.mutants[mutant]:
            data = self.ctx.mutants[mutant]['vsimulation']
            if data['auto-timeout']:
                return -1
            if 'matches' in data:
                return data['matches']['vulnerabilities']
        return -1
# --------------------
