# --------------------
import sys
import os.path
import math
import time
import datetime
import copy
import itertools
import statistics
import pulseutils.arith
import pulseutils.files
from pulseutils import logging as log
from . import pprinters as pp
from . import plots
from . import utils
from .engine import SeaticBaseRunner, ContextLoader
from .results import ExportResultsTask, VStatus
from .utils import extract_optimization
# --------------------
class MetaTask:

    def __init__(self, ctx, metactx, logger, sourcekey=''):
        self.ctx = ctx
        self.metactx = metactx
        self.log = logger
        self.metadata = None
        self.sourcekey = sourcekey

    def execute(self):
        self._execute()

    def _execute(self):
        raise NotImplementedError(self)

    def get_table(self, elements, sortkey=None):
        table = { key : [] for key, _, _ in elements }
        table[self.sourcekey] = []
        for mctx, builder in self.metadata.items():
            for mutant in sorted(builder.ctx.mutants.keys(), key=sortkey):
                table[self.sourcekey].append((builder, mutant))
                for key, kgetter, kformatter in elements:
                    pval = kgetter(builder, mutant, builder.ctx.mutants[mutant])
                    table[key].append(kformatter(pval) if kformatter is not None else pval)
        return table

    def aggregate_table(self, table, categories):
        atable = { key : [] for key in table if key != self.sourcekey }
        for ownership, aggregators, formatters in categories:
            for key, vlist in table.items():
                if key != self.sourcekey:
                    mlist = [ m for m in table[self.sourcekey] if ownership(m) ]
                    if len(mlist) > 0:
                        aggregator = aggregators[key]
                        avalue = aggregator([ vlist[i] for i in (table[self.sourcekey].index(m) for m in mlist)])
                        formatter = formatters[key]
                        atable[key].append(formatter(avalue) if formatter is not None else avalue)
                    else:
                        atable[key].append('no value')
        return atable
# --------------------
class MetaDataTask(MetaTask):

    def extract_data(self):
        self.metadata = { mctx : self.extract_data_from(ctx) for mctx, ctx in self.metactx.items() }

    def extract_data_from(self, ctx):
        raise NotImplementedError(self)

    def execute(self):
        self.extract_data()
        super().execute()
# --------------------
class ResultsComparatorMDT(MetaDataTask):

    def extract_data_from(self, ctx):
        return ExportResultsTask(ctx, self.log)

    def _preprocess(self):
        logdir = self.ctx['target.result-svg']
        if logdir and not os.path.isdir(logdir):
            os.makedirs(logdir)

    def _execute(self):
        self._preprocess()
        for command in self.ctx['opt.meta_script']:
            cname = '_{}'.format(command.strip())
            try:
                getattr(self, cname)()
            except AttributeError as e:
                self.log.error('unknown meta script command: {}'.format(command))
                raise e

    def _execute_all(self):
        self._print_vulnerability_tables()
        self._print_local_vtables()
        self._print_local_vtables(mode='_necessary')
        self._print_local_ttables()
        self._print_severity_tables()
        self._print_abduction_tables()
        self._print_abduction_detailedv_tables()
        self._print_onvuln_abduction_tables()
        self._print_bysource_tables()
        #self._print_match_tables()
        self._generate_vsimulation_list()
        self._generate_split_vsimulation_list()
        self._export_survival_data()

    def _generate_vsimulation_list(self):
        self.log.info('generate vsimulation vulnerabilities list file in vsimulation-vuln-list.txt')
        with open('vsimulation-vuln-list.txt', 'w') as stream:
            for mctx, builder in self.metadata.items():
                for mutant in builder.ctx.mutants.keys():
                    if builder.get_merged_vstatus(mutant, 'vsimu') == VStatus.Vuln:
                        stream.write('{}:{}\n'.format(builder.ctx['source'], mutant))

    def _generate_split_vsimulation_list(self):
        self.log.info('generate split vsimulation vulnerabilities list files')
        for mctx, builder in self.metadata.items():
            filename = '{}-vsimulation-vuln-list.txt'.format(pulseutils.files.flatten_path(pulseutils.files.deprefixate(builder.ctx['source'])))
            self.log.info(f'generate vsimulation vulnerabilities list for {filename}')
            with open(filename, 'w') as stream:
                for mutant in builder.ctx.mutants.keys():
                    if builder.get_merged_vstatus(mutant, 'vsimu') == VStatus.Vuln:
                        stream.write('{}:{}\n'.format(pulseutils.files.deprefixate(builder.ctx['source']), pulseutils.files.deprefixate(mutant)))

    def _export_survival_data(self):
        self.log.info('generate survival data file in survival-rse.data')
        self.log.info('generate survival data file in survival-abd.data')
        stream_rse = open('survival-rse.data', 'w')
        stream_abd = open('survival-abd.data', 'w')
        for mctx, builder in self.metadata.items():
            for mutant in builder.ctx.mutants.keys():
                if builder.get_merged_vstatus(mutant, 'robust') == VStatus.Vuln:
                    tvalue = builder.ctx.mutants[mutant]['binsec-robust']['time']
                    stream_rse.write('{}\n'.format(tvalue))
                    stream_abd.write('{}\n'.format(tvalue))
                elif builder.get_merged_vstatus(mutant, 'abduction') == VStatus.Vuln:
                    try:
                        tvalue = builder.ctx.mutants[mutant]['abducer']['statistics']['time-first-solution']
                    except KeyError:
                        tvalue = -1 # TODO check value consistency
                    stream_abd.write('{}\n'.format(tvalue))
        stream_rse.close()
        stream_abd.close()

    def _print_match_tables(self):
        self.log.info('print match tables')
        tools = ('binsec', 'vsimu', 'abduction', 'simu', 'robust')
        owner = lambda optl : lambda m : optl in m[0].ctx['source']
        for t1, t2 in itertools.combinations(tools, 2):
            elements = [
                    ('#', lambda b, m, md: 1, None),
                    ('?', lambda b, m, md: VStatus.Unknown in (b.get_merged_vstatus(m, t1), b.get_merged_vstatus(m, t2)), None),
                    ('match', lambda b, m, md: b.get_merged_vstatus(m, t1) == b.get_merged_vstatus(m, t2) and b.get_merged_vstatus(m, t1) != VStatus.Unknown, None),
                    ('{} !in {}'.format(t1, t2), lambda b, m, md: b.get_merged_vstatus(m, t1) == VStatus.Vuln and b.get_merged_vstatus(m, t2) != VStatus.Vuln, None),
                    ('{} !in {}'.format(t2, t1), lambda b, m, md: b.get_merged_vstatus(m, t2) == VStatus.Vuln and b.get_merged_vstatus(m, t1) != VStatus.Vuln, None),
            ]
            table = self.get_table(elements)
            aggregators = { k : sum for k in (e[0] for e in elements) }
            formatters = { k : None for k in (e[0] for e in elements) }
            categories = [ (owner(optl), aggregators, formatters) for optl in ('O0', 'O1', 'O2', 'O3', 'Os') ]
            categories.append((lambda m: True, aggregators, formatters))
            atable = self.aggregate_table(table, categories)
            firstcols = ['O0', 'O1', 'O2', 'O3', 'Os', 'total']
            self.log.info('results matching tables for {} -> {}'.format(t1, t2))
            pp.print_pretty_table(atable, sys.stdout, aslist=True, bdr=self.ctx['opt.rpp-bdr'], use_maxlen=False, split=True, firstcol=firstcols, withtotal=False)

    def _print_severity_tables(self):
        self.log.info('print severity tables')
        validator = lambda b, m, md: (b.get_vseverity(m, 'binsec') >= 0 and
                                      b.get_vseverity(m, 'robust') >= 0 and
                                      b.get_vseverity(m, 'abduction') >= 0 and
                                      b.get_vseverity(m, 'simu') >= 0 and
                                      b.get_vseverity(m, 'vsimu') >= 0)
        vseverity_getter = lambda tool, b, m, md: b.get_vseverity(m, tool) #if validator(b, m, md) else -1
        pseverity_getter = lambda tool, b, m, md: b.get_pseverity(m, tool) #if validator(b, m, md) else -1
        elements = [
                ('#', lambda b, m, md: 1, None),
                ('SE', lambda b, m, md: vseverity_getter('binsec', b, m, md), None),
                ('RSE', lambda b, m, md: vseverity_getter('robust', b, m, md), None),
                ('Abd-O', lambda b, m, md: vseverity_getter('abduction', b, m, md), None),
                ('Abd-P', lambda b, m, md: pseverity_getter('abduction', b, m, md), None),
                ('Sim', lambda b, m, md: vseverity_getter('simu', b, m, md), None),
                ('Sim*', lambda b, m, md: vseverity_getter('vsimu', b, m, md), None),
        ]
        table = self.get_table(elements)
        severities = set()
        for tool in ('SE', 'RSE', 'Abd-O', 'Abd-P', 'Sim', 'Sim*'):
            severities = severities | set(table[tool])
        stables = {}
        if self.ctx['opt.ranged_severity']:
            couples = { (-100, 0), (0, 1), (1, 2) }
            severities = { s for s in severities if s >= 2 }
            severities = sorted(severities)
            maxval = severities.pop(-1)
            couples.add((maxval, maxval+1))
            group_size = 5
            residual = len(severities) % group_size
            if self.ctx['opt.auto_severity_classes']:
                while len(severities) >= group_size:
                    gprange = []
                    for _ in range(group_size):
                        gprange.append(severities.pop(0))
                    couples.add((gprange[0], gprange[-1]))
                    severities.insert(0, gprange[-1])
                if len(severities) != 0:
                    couples.add((severities[0], maxval))
            else:
                minsev = 0
                while minsev <= 1:
                    minsev = severities.pop(0)
                couples.add((minsev, int(0.0001*maxval)))
                couples.add((int(0.0001*maxval), int(0.001*maxval)))
                couples.add((int(0.001*maxval), int(0.01*maxval)))
                couples.add((int(0.01*maxval), int(0.05*maxval)))
                couples.add((int(0.05*maxval), int(0.1*maxval)))
                couples.add((int(0.1*maxval), int(0.5*maxval)))
                couples.add((int(0.5*maxval), maxval))
            severities = couples
        for severity in severities:
            elements = [
                    ('#', lambda b, m, md: 1, None),
                    ('SE', lambda b, m, md: severity[0] <= vseverity_getter('binsec', b, m, md), None),
                    ('RSE', lambda b, m, md: severity[0] <= vseverity_getter('robust', b, m, md), None),
                    ('Abd-O', lambda b, m, md: severity[0] <= vseverity_getter('abduction', b, m, md), None),
                    ('Abd-P', lambda b, m, md: severity[0] <= pseverity_getter('abduction', b, m, md), None),
                    ('Sim', lambda b, m, md: severity[0] <= vseverity_getter('simu', b, m, md), None),
                    ('Sim*', lambda b, m, md: severity[0] <= vseverity_getter('vsimu', b, m, md), None),
            ] if self.ctx['opt.cumulative_severity'] and severity[0] > 0 else [
                    ('#', lambda b, m, md: 1, None),
                    ('SE', lambda b, m, md: severity[0] <= vseverity_getter('binsec', b, m, md) < severity[1], None),
                    ('RSE', lambda b, m, md: severity[0] <= vseverity_getter('robust', b, m, md) < severity[1], None),
                    ('Abd-O', lambda b, m, md: severity[0] <= vseverity_getter('abduction', b, m, md) < severity[1], None),
                    ('Abd-P', lambda b, m, md: severity[0] <= pseverity_getter('abduction', b, m, md) < severity[1], None),
                    ('Sim', lambda b, m, md: severity[0] <= vseverity_getter('simu', b, m, md) < severity[1], None),
                    ('Sim*', lambda b, m, md: severity[0] <= vseverity_getter('vsimu', b, m, md) < severity[1], None),
            ] if self.ctx['opt.ranged_severity'] or self.ctx['opt.cumulative_severity'] else [
                    ('#', lambda b, m, md: 1, None),
                    ('SE', lambda b, m, md: vseverity_getter('binsec', b, m, md) == severity, None),
                    ('RSE', lambda b, m, md: vseverity_getter('robust', b, m, md) == severity, None),
                    ('Abd-O', lambda b, m, md: vseverity_getter('abduction', b, m, md) == severity, None),
                    ('Abd-P', lambda b, m, md: pseverity_getter('abduction', b, m, md) == severity, None),
                    ('Sim', lambda b, m, md: vseverity_getter('simu', b, m, md) == severity, None),
                    ('Sim*', lambda b, m, md: vseverity_getter('vsimu', b, m, md) == severity, None),
            ]
            stable = self.get_table(elements)
            aggregators = { k : sum for k in (e[0] for e in elements) }
            formatters = { k : None for k in (e[0] for e in elements) }
            categories = [ (lambda m: True, aggregators, formatters) ]
            stables[severity] = self.aggregate_table(stable, categories)
        rtable = { k : [] for k in ('#', 'SE', 'RSE', 'Abd-O', 'Abd-P', 'Sim', 'Sim*') }
        sevs = []
        for severity in sorted(severities):
            stable = stables[severity]
            if self.ctx['opt.cumulative_severity']:
                sevs.append(self._format_cumulative_severity(severity, maxval))
            elif self.ctx['opt.ranged_severity']:
                sevs.append(self._format_ranged_severity(severity, maxval))
            else:
                sevs.append(severity)
            for k in stable:
                rtable[k].extend(stable[k])
        pp.print_pretty_table(rtable, sys.stdout, aslist=True, bdr=self.ctx['opt.rpp-bdr'], use_maxlen=False, split=True, firstcol=sevs, withtotal=False)

    def _format_ranged_severity(self, severity, maxval):
        percentify = lambda v : pulseutils.arith.percentify(v, maxval)
        if severity[0] < 0:
            return 'unknown'
        if severity[1] - severity[0] == 1:
            if severity[0] <= 1:
                return '{} input'.format(severity[0])
            return '{}%'.format(percentify(severity[0]))
        return '[{}% ; {}%['.format(percentify(severity[0]), percentify(severity[1]))

    def _format_cumulative_severity(self, severity, maxval):
        percentify = lambda v : pulseutils.arith.percentify(v, maxval)
        if severity[0] < 0:
            return 'unknown'
        if severity[0] <= 0:
            return '{} input'.format(severity[0])
        if severity[0] <= 1:
            return '>= {} input'.format(severity[0])
        return '{} {}%'.format('>=' if severity[0] < maxval else '', percentify(severity[0]))

    def _print_bysource_tables(self):
        self.log.info('print by-source summary tables')
        stable = self.get_table([('source', lambda b, m, md: b.ctx['source'], None)])
        sources = list(set(stable['source']))
        sources.sort()
        elements = [
                ('#', lambda b, m, md: 1, None),
                ('V. SE', lambda b, m, md: b.get_merged_vstatus(m, 'binsec') == VStatus.Vuln, None),
                ('V. RSE', lambda b, m, md: b.get_merged_vstatus(m, 'robust') == VStatus.Vuln, None),
                ('V. Abd', lambda b, m, md: b.get_merged_vstatus(m, 'abduction') == VStatus.Vuln, None),
                ('V. Sim', lambda b, m, md: b.get_merged_vstatus(m, 'simu') == VStatus.Vuln, None),
                ('V. Sim*', lambda b, m, md: b.get_merged_vstatus(m, 'vsimu') == VStatus.Vuln, None),
        ]
        vtable = self.get_table(elements)
        owner = lambda src : lambda m : m[0].ctx['source'] == src
        aggregators = { k : sum for k in (e[0] for e in elements) }
        formatters = { k : None for k in (e[0] for e in elements) }
        categories = [ (owner(source), aggregators, formatters) for source in sources ]
        avtable = self.aggregate_table(vtable, categories)
        self.log.info('summarized by-source results table')
        pp.print_pretty_table(avtable, sys.stdout, aslist=True, bdr=self.ctx['opt.rpp-bdr'], use_maxlen=False, split=True, firstcol=sources, withtotal=False)

    def _print_abduction_detailedv_tables(self, split=True, percentify=True):
        self.log.info('print detailed abduction vulnerability tables')
        velements = [
                ('#', lambda b, m, md: b.get_merged_vstatus(m, 'binsec') == VStatus.Vuln, None),
                ('Abd (suf) %', lambda b, m, md: (b.get_merged_vstatus(m, 'binsec') == VStatus.Vuln,
                                                b.get_merged_vstatus(m, 'abduction') == VStatus.Vuln), None),
                ('Abd (nec) %', lambda b, m, md: (b.get_merged_vstatus(m, 'binsec') == VStatus.Vuln,
                                                b.get_merged_vstatus(m, 'abduction_necessary') == VStatus.Vuln), None),
                ('Abd (any) %', lambda b, m, md: (b.get_merged_vstatus(m, 'binsec') == VStatus.Vuln,
                                                b.get_merged_vstatus(m, 'abduction') == VStatus.Vuln or b.get_merged_vstatus(m, 'abduction_necessary') == VStatus.Vuln), None),
                ('Abd (weakest) %', lambda b, m, md: (b.get_merged_vstatus(m, 'binsec') == VStatus.Vuln,
                                                    b.get_merged_vstatus(m, 'abduction_nas') == VStatus.Vuln), None),
                ('RSE %', lambda b, m, md: (b.get_merged_vstatus(m, 'binsec') == VStatus.Vuln,
                                          b.get_merged_vstatus(m, 'robust') == VStatus.Vuln), None),
                #('Abd (w/ regs)', lambda b, m, md: (b.get_merged_vstatus(m, 'binsec') == VStatus.Vuln,
                #                                    b.get_merged_vstatus(m, 'abduction_registers') == VStatus.Vuln), None),
                #('Abd (w/ consts)', lambda b, m, md: (b.get_merged_vstatus(m, 'binsec') == VStatus.Vuln,
                #                                    b.get_merged_vstatus(m, 'abduction_constants') == VStatus.Vuln), None),
        ]
        vtable = self.get_table(velements)
        owner = lambda optl : lambda m : optl in m[0].ctx['source']
        if percentify:
            aggregators = { k : (lambda l: 100*(sum((t[1] for t in l))/sum((t[0] for t in l)))) for k in (e[0] for e in velements) }
        else:
            aggregators = { k : (lambda l: (sum((t[1] for t in l)))) for k in (e[0] for e in velements) }
        aggregators['#'] = sum
        #aggregators['Abd (all)'] = lambda l: 100*statistics.mean(l)
        #aggregators['Abd (nec)'] = lambda l: 100*statistics.mean(l)
        formatters = { k : (lambda v: round(v, 1)) for k in (e[0] for e in velements) }
        categories = [ (owner(optl), aggregators, formatters) for optl in ('O0', 'O1', 'O2', 'O3', 'Os') ] if split else []
        categories.append((lambda m: True, aggregators, formatters))
        avtable = self.aggregate_table(vtable, categories)
        firstcols = ['O0', 'O1', 'O2', 'O3', 'Os', 'total'] if split else ['total']
        self.log.info('table of detailed aggregated abduction vulnerability percentages')
        pp.print_pretty_table(avtable, sys.stdout, aslist=True, bdr=self.ctx['opt.rpp-bdr'], use_maxlen=False, split=True, firstcol=firstcols, withtotal=False)

    def _print_abduction_detailedv_tables_nosplit(self):
        self._print_abduction_detailedv_tables(split=False)

    def _print_abduction_detailedv_tables_nosplit_nopercent(self):
        self._print_abduction_detailedv_tables(split=False, percentify=False)

    def _print_local_vtables(self, mode=''):
        self.log.info('print local vulnerability tables')
        velements = [
                ('#', lambda b, m, md: b.get_merged_vstatus(m, 'binsec') == VStatus.Vuln, None),
                ('RSE', lambda b, m, md: (b.get_merged_vstatus(m, 'binsec') == VStatus.Vuln, b.get_merged_vstatus(m, 'robust') == VStatus.Vuln), None),
                ('Abd', lambda b, m, md: (b.get_merged_vstatus(m, 'binsec') == VStatus.Vuln, b.get_merged_vstatus(m, 'abduction{}'.format(mode)) == VStatus.Vuln), None),
                ('Abd w/o RSE', lambda b, m, md: (b.get_merged_vstatus(m, 'binsec') == VStatus.Vuln,
                                                  b.get_merged_vstatus(m, 'abduction{}'.format(mode)) == VStatus.Vuln and not b.get_merged_vstatus(m, 'robust') == VStatus.Vuln), None),
        ]
        vtable = self.get_table(velements)
        owner = lambda optl : lambda m : optl in m[0].ctx['source']
        aggregators = { k : (lambda l: 100*statistics.mean([v[1] for v in l if v[0]])) for k in (e[0] for e in velements) }
        aggregators['#'] = sum
        formatters = { k : (lambda v: round(v, 1)) for k in (e[0] for e in velements) }
        categories = [ (owner(optl), aggregators, formatters) for optl in ('O0', 'O1', 'O2', 'O3', 'Os') ]
        categories.append((lambda m: True, aggregators, formatters))
        avtable = self.aggregate_table(vtable, categories)
        firstcols = ['O0', 'O1', 'O2', 'O3', 'Os', 'total']
        self.log.info('table of aggregated local vulnerability percentages (mode={})'.format(mode))
        pp.print_pretty_table(avtable, sys.stdout, aslist=True, bdr=self.ctx['opt.rpp-bdr'], use_maxlen=False, split=True, firstcol=firstcols, withtotal=False)

    def _print_local_ttables(self):
        self.log.info('print local time tables')
        telements = [
                ('#', lambda b, m, md: b.get_merged_vstatus(m, 'abduction') == VStatus.Vuln, None),
                ('SE', lambda b, m, md: (b.get_merged_vstatus(m, 'abduction') == VStatus.Vuln, md['binsec']['time'] if 'binsec' in md else 0), None),
                ('Abd', lambda b, m, md: (b.get_merged_vstatus(m, 'abduction') == VStatus.Vuln, b.get_corrected_abducer_time(m)), None),
        ]
        ttable = self.get_table(telements)
        owner = lambda optl : lambda m : optl in m[0].ctx['source']
        taggregators = { k : lambda l : sum([v[1] for v in l if v[0]]) for k in (e[0] for e in telements) }
        taggregators['#'] = sum
        tformatters = { k : (lambda v: datetime.timedelta(seconds=round(v))) for k in (e[0] for e in telements) }
        tformatters['#'] = None
        tcategories = [ (owner(optl), taggregators, tformatters) for optl in ('O0', 'O1', 'O2', 'O3', 'Os') ]
        tcategories.append((lambda m: True, taggregators, tformatters))
        attable = self.aggregate_table(ttable, tcategories)
        meanagg = { k : lambda l : statistics.mean([v[1] for v in l if v[0]]) for k in (e[0] for e in telements) }
        mednagg = { k : lambda l : statistics.median([v[1] for v in l if v[0]]) for k in (e[0] for e in telements) }
        meanagg['#'] = sum
        mednagg['#'] = sum
        meancats = [ (owner(optl), meanagg, tformatters) for optl in ('O0', 'O1', 'O2', 'O3', 'Os') ]
        meancats.append((lambda m: True, meanagg, tformatters))
        medncats = [ (owner(optl), mednagg, tformatters) for optl in ('O0', 'O1', 'O2', 'O3', 'Os') ]
        medncats.append((lambda m: True, mednagg, tformatters))
        meanttable = self.aggregate_table(ttable, meancats)
        mednttable = self.aggregate_table(ttable, medncats)
        attable['Sum (Abd)'] = attable['Abd']
        attable['Sum (SE)'] = attable['SE']
        attable.pop('Abd')
        attable.pop('SE')
        attable['Mean (Abd)'] = meanttable['Abd']
        attable['Mean (SE)'] = meanttable['SE']
        attable['Median (Abd)'] = mednttable['Abd']
        attable['Median (SE)'] = mednttable['SE']
        firstcols = ['O0', 'O1', 'O2', 'O3', 'Os', 'total']
        self.log.info('vuln only table of computation times')
        pp.print_pretty_table(attable, sys.stdout, aslist=True, bdr=self.ctx['opt.rpp-bdr'], use_maxlen=False, split=True, firstcol=firstcols, withtotal=False)

    def _print_vulnerability_tables(self):
        self.log.info('print vulnerability tables')
        velements = [
                ('#', lambda b, m, md: 1, None),
                ('SE', lambda b, m, md: b.get_merged_vstatus(m, 'binsec') == VStatus.Vuln, None),
                ('RSE', lambda b, m, md: b.get_merged_vstatus(m, 'robust') == VStatus.Vuln, None),
                ('Abd', lambda b, m, md: b.get_merged_vstatus(m, 'abduction') == VStatus.Vuln, None),
                ('Sim', lambda b, m, md: b.get_merged_vstatus(m, 'simu') == VStatus.Vuln, None),
                ('Sim*', lambda b, m, md: b.get_merged_vstatus(m, 'vsimu') == VStatus.Vuln, None),
        ]
        uelements = [
                ('#', lambda b, m, md: 1, None),
                ('SE', lambda b, m, md: b.get_merged_vstatus(m, 'binsec') == VStatus.Unknown, None),
                ('RSE', lambda b, m, md: b.get_merged_vstatus(m, 'robust') == VStatus.Unknown, None),
                ('Abd', lambda b, m, md: b.get_merged_vstatus(m, 'abduction') == VStatus.Unknown, None),
                ('Sim', lambda b, m, md: b.get_merged_vstatus(m, 'simu') == VStatus.Unknown, None),
                ('Sim*', lambda b, m, md: b.get_merged_vstatus(m, 'vsimu') == VStatus.Unknown, None),
        ]
        abdtstatget = (lambda b, m, md, stat : md['binsec-robust']['time'] if 'binsec-robust' in md and b.get_merged_vstatus(m, 'robust') == VStatus.Vuln
                                                                           else
                                               md['abducer']['statistics'][stat] if 'abducer' in md and 'statistics' in md['abducer'] and stat in md['abducer']['statistics']
                                                                           else 0)
        telements = [
                ('#', lambda b, m, md: 1, None),
                ('SE', lambda b, m, md: md['binsec']['time'] if 'binsec' in md else 0, None),
                ('RSE', lambda b, m, md: md['binsec-robust']['time'] if 'binsec-robust' in md else 0, None),
                ('Abd', lambda b, m, md: b.get_corrected_abducer_time(m), None),
                ('Abd-fsol', lambda b, m, md: abdtstatget(b, m, md, 'time-first-solution'), None),
                ('Abd-fnec', lambda b, m, md: abdtstatget(b, m, md, 'time-first-necessary'), None),
                ('Abd-lsol', lambda b, m, md: abdtstatget(b, m, md, 'time-last-solution'), None),
                ('Abd-lnec', lambda b, m, md: abdtstatget(b, m, md, 'time-last-necessary'), None),
                ('Sim', lambda b, m, md: md['simulation']['time'] if 'simulation' in md else 0, None),
                ('Sim*', lambda b, m, md: md['vsimulation']['time'] if 'vsimulation' in md else 0, None),
        ]
        vtable = self.get_table(velements)
        utable = self.get_table(uelements)
        ttable = self.get_table(telements)
        owner = lambda optl : lambda m : optl in m[0].ctx['source']
        aggregators = { k : (lambda l: 100*statistics.mean(l)) for k in (e[0] for e in velements) }
        #aggregators = { k : sum for k in (e[0] for e in velements) }
        aggregators['#'] = sum
        taggregators = { k : sum for k in (e[0] for e in telements) }
        formatters = { k : (lambda v: round(v, 1)) for k in (e[0] for e in velements) }
        tformatters = { k : (lambda v: datetime.timedelta(seconds=round(v))) for k in (e[0] for e in telements) }
        tformatters['#'] = None
        categories = [ (owner(optl), aggregators, formatters) for optl in ('O0', 'O1', 'O2', 'O3', 'Os') ]
        categories.append((lambda m: True, aggregators, formatters))
        tcategories = [ (owner(optl), taggregators, tformatters) for optl in ('O0', 'O1', 'O2', 'O3', 'Os') ]
        tcategories.append((lambda m: True, taggregators, tformatters))
        avtable = self.aggregate_table(vtable, categories)
        autable = self.aggregate_table(utable, categories)
        attable = self.aggregate_table(ttable, tcategories)
        firstcols = ['O0', 'O1', 'O2', 'O3', 'Os', 'total']
        self.log.info('table of aggregated vulnerability percentages')
        pp.print_pretty_table(avtable, sys.stdout, aslist=True, bdr=self.ctx['opt.rpp-bdr'], use_maxlen=False, split=True, firstcol=firstcols, withtotal=False)
        self.log.info('table of aggregated tool unknowns')
        pp.print_pretty_table(autable, sys.stdout, aslist=True, bdr=self.ctx['opt.rpp-bdr'], use_maxlen=False, split=True, firstcol=firstcols, withtotal=False)
        self.log.info('table of total computation times')
        pp.print_pretty_table(attable, sys.stdout, aslist=True, bdr=self.ctx['opt.rpp-bdr'], use_maxlen=False, split=True, firstcol=firstcols, withtotal=False)
        # Mean and median computation times
        vulnowner = lambda optl : lambda m : optl in m[0].ctx['source'] and m[0].ctx.is_vulnerable(m[1])
        meanagg = { k : statistics.mean for k in (e[0] for e in telements) }
        mednagg = { k : statistics.median for k in (e[0] for e in telements) }
        meanagg['#'] = sum
        mednagg['#'] = sum
        meancats = [ (vulnowner(optl), meanagg, tformatters) for optl in ('O0', 'O1', 'O2', 'O3', 'Os') ]
        meancats.append((lambda m: m[0].ctx.is_vulnerable(m[1]), meanagg, tformatters))
        medncats = [ (vulnowner(optl), mednagg, tformatters) for optl in ('O0', 'O1', 'O2', 'O3', 'Os') ]
        medncats.append((lambda m: m[0].ctx.is_vulnerable(m[1]), mednagg, tformatters))
        meanttable = self.aggregate_table(ttable, meancats)
        mednttable = self.aggregate_table(ttable, medncats)
        self.log.info('table of mean vulnerable computation time')
        pp.print_pretty_table(meanttable, sys.stdout, aslist=True, bdr=self.ctx['opt.rpp-bdr'], use_maxlen=False, split=True, firstcol=firstcols, withtotal=False)
        self.log.info('table of median vulnerable computation time')
        pp.print_pretty_table(mednttable, sys.stdout, aslist=True, bdr=self.ctx['opt.rpp-bdr'], use_maxlen=False, split=True, firstcol=firstcols, withtotal=False)
        if self.ctx['opt.plots']:
            self._generate_pulse_barplots(avtable, autable, attable)
            self._generate_time_histograms(vtable, utable, ttable)
            self._generate_survival_plots(vtable, utable, ttable)
            self._generate_variating_plots(vtable, utable, ttable)

    def _get_status_color(self, vuln, unkn):
        return 'r' if vuln else 'y' if unkn else 'g'

    def _generate_variating_plots(self, vtable, utable, ttable):
        self.log.info('generating variating statistics time plots')
        for tool, step in (('SE', 1), ('RSE', 1), ('Abd', 1), ('Sim', 1), ('Sim*', 10)):
            for stat in (sum, statistics.mean, statistics.median):
                filename = os.path.join(self.ctx['target.result-svg'], 'mutant-variating-{}-{}-time.pdf'.format(tool.replace('*', '-star').lower(), stat.__name__))
                self.log.info('writing {}, {} --> {}'.format(tool, stat, filename))
                title = tool if self.ctx['opt.plot_titles'] else ''
                if tool in ('RSE', 'Abd'):
                    rttable = []
                    for index in range(len(ttable[tool])):
                        if vtable['SE'][index]:
                            rttable.append(ttable[tool][index])
                    plots.generate_cummulative_timeplots([rttable], title, filename, step, stat, labels=['total'], cummulative=stat == sum)
                else:
                    plots.generate_cummulative_timeplots([ttable[tool]], title, filename, step, stat, labels=['total'], cummulative=stat == sum)

    def _generate_time_histograms(self, vtable, utable, ttable):
        self.log.info('generating tool mutant times histograms')
        for tool in ('SE', 'RSE', 'Abd', 'Abd-fsol', 'Abd-fnec', 'Abd-lsol', 'Abd-lnec', 'Sim', 'Sim*'):
            title = 'Mutants Computation Time ({})'.format(tool) if self.ctx['opt.plot_titles'] else ''
            filename = os.path.join(self.ctx['target.result-svg'], 'mutant-ctime-histogram-{}-{}-bins.pdf'.format(tool.replace('*', '-star').lower(), '{}'))
            colors = []
            color_labels = dict(r='vulnerable mutant', y='inconclusive', g='non vulnerable mutant')
            for index in range(len(ttable[tool])):
                toolcore = tool.split('-')[0]
                colors.append(self._get_status_color(vtable[toolcore][index], utable[toolcore][index]))
            self.log.info('writing {} --> {}'.format(title.lower(), filename))
            if tool in ('RSE', 'Abd') or tool.startswith('Abd'):
                # Draw for SE vulnerable elements only
                rttable, rcolors = [], []
                for index in range(len(ttable[tool])):
                    if vtable['SE'][index]:
                        rttable.append(ttable[tool][index])
                        rcolors.append(colors[index])
                plots.generate_histograms(rttable, title, filename, colors=rcolors, color_labels=color_labels)
            else:
                plots.generate_histograms(ttable[tool], title, filename, colors=colors, color_labels=color_labels)

    def _generate_pulse_barplots(self, vtable, utable, ttable):
        self.log.info('generating PULSE categorization barplots')
        values = [ vtable[tool][:-1] for tool in ('RSE', 'SE', 'Abd') ]
        filename =  os.path.join(self.ctx['target.result-svg'], 'pulse-barplot.png')
        plots.generate_barplot(values, None, filename, labels=['robust', 'binsec', 'abduction'], xlabels=['O0', 'O1', 'O2', 'O3', 'Os'])

    def _generate_survival_plots(self, vtable, utable, ttable):
        self.log.info('generating tool mutants survival and cdf plots')
        sanitizedtt = dict()
        sanvulntt  = dict()
        sanrobutt = dict()
        tools = ('SE', 'RSE', 'Abd', 'Sim', 'Sim*')
        toolnames = ('Binsec', 'Binsec-RSE', 'PyAbd+pin', 'Qemu', 'Qemu+L1')
        for tool in tools:
            if tool in ('RSE', 'Abd'):
                sanitizedtt[tool] = [ ttable[tool][i] + ttable['SE'][i] for i in range(len(ttable[tool])) if not utable['SE'][i] and not utable[tool][i] ]
                sanvulntt[tool] = [ ttable[tool][i] + ttable['SE'][i] for i in range(len(ttable[tool])) if not utable['SE'][i] and vtable[tool][i] ]
                sanrobutt[tool] = [ ttable[tool][i] + ttable['SE'][i] for i in range(len(ttable[tool])) if not utable['SE'][i] and not utable[tool][i] and not vtable[tool][i] ]
            else:
                sanitizedtt[tool] = [ ttable[tool][i] for i in range(len(ttable[tool])) if not utable[tool][i] ]
                sanvulntt[tool] = [ ttable[tool][i] for i in range(len(ttable[tool])) if vtable[tool][i] ]
                sanrobutt[tool] = [ ttable[tool][i] for i in range(len(ttable[tool])) if not utable[tool][i] and not vtable[tool][i] ]
            title = 'Mutants Solved ({})'.format(tool) if self.ctx['opt.plot_titles'] else ''

            filename_c = os.path.join(self.ctx['target.result-svg'], 'mutant-cdf-{}.pdf'.format(tool.replace('*', '-star').lower()))
            self.log.info('writing cdf {} --> {}'.format(title.lower(), filename_c))
            plots.generate_cdf_plot([ttable[tool]], title, filename_c)

            filename_c = os.path.join(self.ctx['target.result-svg'], 'mutant-cdf-sanitized-splitted-{}.pdf'.format(tool.replace('*', '-star').lower()))
            self.log.info('writing splitted sanitized cdf {} --> {}'.format(title.lower(), filename_c))
            plots.generate_cdf_plot([sanitizedtt[tool], sanvulntt[tool], sanrobutt[tool]], title, filename_c, labels=('All', 'Vuln', '!Vuln'))

            filename_c = os.path.join(self.ctx['target.result-svg'], 'mutant-cdf-sanitized-{}.pdf'.format(tool.replace('*', '-star').lower()))
            self.log.info('writing sanitized cdf {} --> {}'.format(title.lower(), filename_c))
            plots.generate_cdf_plot([sanitizedtt[tool]], title, filename_c)

            filename_c = os.path.join(self.ctx['target.result-svg'], 'mutant-cdf-vulns-{}.pdf'.format(tool.replace('*', '-star').lower()))
            self.log.info('writing sanitized vulnerabilities cdf {} --> {}'.format(title.lower(), filename_c))
            plots.generate_cdf_plot([sanvulntt[tool]], title, filename_c)

            filename_s = os.path.join(self.ctx['target.result-svg'], 'mutant-survival-splitted-{}.pdf'.format(tool.replace('*', '-star').lower()))
            self.log.info('writing splitted survival {} --> {}'.format(title.lower(), filename_s))
            plots.generate_survival_plot([sanitizedtt[tool], sanvulntt[tool], sanrobutt[tool]], title, filename_s, labels=('All', 'Vuln', '!Vuln'))

            filename_s = os.path.join(self.ctx['target.result-svg'], 'mutant-survival-{}.pdf'.format(tool.replace('*', '-star').lower()))
            self.log.info('writing survival {} --> {}'.format(title.lower(), filename_s))
            plots.generate_survival_plot([sanitizedtt[tool]], title, filename_s)

            filename_s = os.path.join(self.ctx['target.result-svg'], 'mutant-survival-vulns-{}.pdf'.format(tool.replace('*', '-star').lower()))
            self.log.info('writing vulnerabilities survival {} --> {}'.format(title.lower(), filename_s))
            plots.generate_survival_plot([sanvulntt[tool]], title, filename_s)

        title = 'Mutants Solved' if self.ctx['opt.plot_titles'] else ''
        filename_c1 = os.path.join(self.ctx['target.result-svg'], 'mutant-cdf-all.pdf')
        filename_c2 = os.path.join(self.ctx['target.result-svg'], 'mutant-cdf-sanitized-all.pdf')
        filename_s = os.path.join(self.ctx['target.result-svg'], 'mutant-survival-all.pdf')
        filename_v1 = os.path.join(self.ctx['target.result-svg'], 'mutant-cdf-sanitized-vulns-all.pdf')
        filename_v2 = os.path.join(self.ctx['target.result-svg'], 'mutant-survival-vulns-all.pdf')

        self.log.info('writing cdf {} --> {}'.format(title.lower(), filename_c1))
        plots.generate_cdf_plot([ttable[tool] for tool in tools], title, filename_c1, labels=toolnames)
        self.log.info('writing sanitized cdf {} --> {}'.format(title.lower(), filename_c2))
        plots.generate_cdf_plot([sanitizedtt[tool] for tool in tools], title, filename_c2, labels=toolnames)
        self.log.info('writing survival {} --> {}'.format(title.lower(), filename_s))
        plots.generate_survival_plot([sanitizedtt[tool] for tool in tools], title, filename_s, labels=toolnames)

        self.log.info('writing sanitized vulnerabilities cdf {} --> {}'.format(title.lower(), filename_v1))
        plots.generate_cdf_plot([sanvulntt[tool] for tool in tools], title, filename_v1, labels=toolnames)
        self.log.info('writing vulnerabilities survival {} --> {}'.format(title.lower(), filename_v2))
        plots.generate_survival_plot([sanvulntt[tool] for tool in tools], title, filename_v2, labels=toolnames)

        filename_ac1 = os.path.join(self.ctx['target.result-svg'], 'mutant-cdf-sanitized-abdsim-star.pdf')
        filename_ac2 = os.path.join(self.ctx['target.result-svg'], 'mutant-cdf-vulns-abdsim-star.pdf')
        filename_as1 = os.path.join(self.ctx['target.result-svg'], 'mutant-survival-abdsim-star.pdf')
        filename_as2 = os.path.join(self.ctx['target.result-svg'], 'mutant-survival-vulns-cdf-abdsim-star.pdf')

        self.log.info('writing sanitized abd vs sim* cdf {} --> {}'.format(title.lower(), filename_ac1))
        plots.generate_cdf_plot([sanitizedtt['Abd'], sanitizedtt['Sim*']], title, filename_ac1, labels=('Abd', 'Sim*'))
        self.log.info('writing vulnerabilities abd vs sim* cdf {} --> {}'.format(title.lower(), filename_ac2))
        plots.generate_cdf_plot([sanvulntt['Abd'], sanvulntt['Sim*']], title, filename_ac2, labels=('Abd', 'Sim*'))
        self.log.info('writing abd vs sim* survival {} --> {}'.format(title.lower(), filename_as1))
        plots.generate_survival_plot([sanitizedtt['Abd'], sanitizedtt['Sim*']], title, filename_as1, labels=('Abd', 'Sim*'))
        self.log.info('writing vulnerabilities abd vs sim* survival {} --> {}'.format(title.lower(), filename_as2))
        plots.generate_survival_plot([sanvulntt['Abd'], sanvulntt['Sim*']], title, filename_as2, labels=('Abd', 'Sim*'))

    def _print_onvuln_abduction_tables(self):
        self._print_onvuln_filtered_abduction_tables('abd vulnerable only', lambda b, m, md: b.get_merged_vstatus(m, 'abduction') == VStatus.Vuln and not md['abducer']['timeout'])
        self._print_onvuln_filtered_abduction_tables('on binsec vulns', lambda b, m, md: b.get_merged_vstatus(m, 'binsec') == VStatus.Vuln and (b.get_merged_vstatus(m, 'abduction') != VStatus.Unknown or md['abducer']['timeout']))
        self._print_onvuln_filtered_abduction_tables('any abd vuln', lambda b, m, md: b.get_merged_vstatus(m, 'abduction') == VStatus.Vuln)
        self._print_onvuln_filtered_abduction_tables('weakest', lambda b, m, md: b.get_merged_vstatus(m, 'abduction') == VStatus.Vuln and md['abducer']['exact'])
        self._print_onvuln_filtered_abduction_tables('weakest non rse', lambda b, m, md: b.get_merged_vstatus(m, 'abduction') == VStatus.Vuln and md['abducer']['exact'] and b.get_merged_vstatus(m, 'robust') != VStatus.Vuln)

    def _print_onvuln_abduction_tables_static_nosplits(self):
        #sys.stdout.write('\n\nAverage on Abduction Final Characterization Only\n\n')
        #self._print_onvuln_filtered_abduction_tables('abd vulnerable only', lambda b, m, md: b.get_merged_vstatus(m, 'abduction') == VStatus.Vuln and not md['abducer']['timeout'], splits=False, print_median=False)
        sys.stdout.write('\n\nAverage on Binsec Reachability\n\n')
        self._print_onvuln_filtered_abduction_tables('on binsec vulns', lambda b, m, md: b.get_merged_vstatus(m, 'binsec') == VStatus.Vuln and (b.get_merged_vstatus(m, 'abduction') != VStatus.Unknown or md['abducer']['timeout']), splits=False, print_median=False)
        sys.stdout.write('\n\nAverage on Any Abduction Characterization\n\n')
        self._print_onvuln_filtered_abduction_tables('any abd vuln', lambda b, m, md: b.get_merged_vstatus(m, 'abduction') == VStatus.Vuln, splits=False, print_median=False)
        sys.stdout.write('\n\nAverage on Weakest Abduction Characterization\n\n')
        self._print_onvuln_filtered_abduction_tables('weakest', lambda b, m, md: b.get_merged_vstatus(m, 'abduction') == VStatus.Vuln and md['abducer']['exact'], splits=False, print_median=False)
        #sys.stdout.write('\n\nAverage on Weakest Abduction Characterization not Robustly Reachable\n\n')
        #self._print_onvuln_filtered_abduction_tables('weakest non rse', lambda b, m, md: b.get_merged_vstatus(m, 'abduction') == VStatus.Vuln and md['abducer']['exact'] and b.get_merged_vstatus(m, 'robust') != VStatus.Vuln, splits=False, print_median=False)

    def _print_onvuln_filtered_abduction_tables(self, filtername, filterf, splits=True, print_median=True):
        self.log.info('print local time tables')
        getstat = lambda md, stat : md['abducer']['statistics'][stat] if ('abducer' in md and 'statistics' in md['abducer'] and stat in md['abducer']['statistics']) else 0
        getstatdiff = lambda md, statp, statm : max(md['abducer']['statistics'][statp] - md['abducer']['statistics'][statm], 0) if ('abducer' in md and 'statistics' in md['abducer'] and statp in md['abducer']['statistics'] and statm in md['abducer']['statistics']) else 0
        telements_core = [
                ('#', lambda b, m, md: filterf(b, m, md), None), # and not md['abducer']['timeout'], None),
                ('candidates considered', lambda b, m, md: (filterf(b, m, md), getstat(md, 'candidates-considered')), None),
                ('candidates checked', lambda b, m, md: (filterf(b, m, md), getstat(md, 'candidates-evaluated')), None),
                ('candidates pruned', lambda b, m, md: (filterf(b, m, md), getstatdiff(md, 'candidates-considered', 'candidates-evaluated')), None),
                #('binsec calls', lambda b, m, md: (filterf(b, m, md), getstat(md, 'count-binsec-call')), None),
                #('check calls', lambda b, m, md: (filterf(b, m, md), getstat(md, 'count-minibinsec-call')), None),
                #('variables', lambda b, m, md: (filterf(b, m, md), getstat(md, 'count-variable')), None),
                ('literals', lambda b, m, md: (filterf(b, m, md), getstat(md, 'count-literal')), None),
                ('solution count', lambda b, m, md: (filterf(b, m, md), len(md['abducer']['constraints']) if 'abducer' in md else 0), None),
                ('solution length', lambda b, m, md: (filterf(b, m, md), (statistics.mean((len(c) for c in md['abducer']['constraints'])) if len(md['abducer']['constraints']) > 0 else 0) if 'abducer' in md else 0), None),
                #('oracle time', lambda b, m, md: (filterf(b, m, md),
                #        sum([] if getstat(md, 'times-binsec') == 0 else getstat(md, 'times-binsec'))), None),
                #('total time', lambda b, m, md: (filterf(b, m, md),
                #        md['abducer']['time'] if 'abducer' in md else 0), None),
                #('binsec time', lambda b, m, md: (filterf(b, m, md),
                #        md['binsec']['time'] if 'binsec' in md else 0), None),
                #('robust time', lambda b, m, md: (filterf(b, m, md),
                #        md['binsec-robust']['time'] if 'binsec-robust' in md else 0), None),
        ]
        for telements in ( telements_core[:8], [telements_core[0]] + telements_core[8:] ):
            ttable = self.get_table(telements)
            owner = lambda optl : lambda m : optl in m[0].ctx['source']
            taggregators = { k : lambda l : sum([v[1] for v in l if v[0]]) for k in (e[0] for e in telements) }
            taggregators['#'] = sum
            #tformatters = { k : (lambda v: datetime.timedelta(seconds=round(v))) for k in (e[0] for e in telements) }
            tformatters = { k : lambda m : round(m, 1) if m != 'no value' else m for k in (e[0] for e in telements) }
            tformatters['#'] = None
            tcategories = [ (owner(optl), taggregators, tformatters) for optl in ('O0', 'O1', 'O2', 'O3', 'Os') ] if splits else []
            tcategories.append((lambda m: True, taggregators, tformatters))
            attable = self.aggregate_table(ttable, tcategories)
            meanagg = { k : lambda l : (statistics.mean([v[1] for v in l if v[0]]) if len([v for v in l if v[0]]) else 'no value') for k in (e[0] for e in telements) }
            mednagg = { k : lambda l : (statistics.median([v[1] for v in l if v[0]]) if len([v for v in l if v[0]]) else 'no value') for k in (e[0] for e in telements) }
            meanagg['#'] = sum
            mednagg['#'] = sum
            meancats = [ (owner(optl), meanagg, tformatters) for optl in ('O0', 'O1', 'O2', 'O3', 'Os') ] if splits else []
            meancats.append((lambda m: True, meanagg, tformatters))
            medncats = [ (owner(optl), mednagg, tformatters) for optl in ('O0', 'O1', 'O2', 'O3', 'Os') ] if splits else []
            medncats.append((lambda m: True, mednagg, tformatters))
            meanttable = self.aggregate_table(ttable, meancats)
            mednttable = self.aggregate_table(ttable, medncats)
            firstcols = ['O0', 'O1', 'O2', 'O3', 'Os', 'total'] if splits else ['total']
            self.log.info('abduction statistics on abd-vulnerable mutants (mean) [filter={}]'.format(filtername))
            pp.print_pretty_table(meanttable, sys.stdout, aslist=True, bdr=self.ctx['opt.rpp-bdr'], use_maxlen=False, split=True, firstcol=firstcols, withtotal=False)
            if print_median:
                self.log.info('abduction statistics on abd-vulnerable mutants (median) [filter={}]'.format(filtername))
                pp.print_pretty_table(mednttable, sys.stdout, aslist=True, bdr=self.ctx['opt.rpp-bdr'], use_maxlen=False, split=True, firstcol=firstcols, withtotal=False)

    def _print_abduction_tables(self):
        self.log.info('printing abduction insight tables')
        self.log.warning('time elements of the following table are not RSE-fixed (simulation of an initial RSE check)')
        def abdstatgetter(stat, fun=lambda b, m, md, d: d):
            return (lambda b, m, md:
                fun(b, m, md, md['abducer']['statistics'][stat]) if 'abducer' in md
                                                                    and 'statistics' in md['abducer']
                                                                    and stat in md['abducer']['statistics']
                else 0)
        celements = [
                ('#', lambda b, m, md: 1, None),
                ('precandidates', abdstatgetter('candidates-considered'), None),
                ('literals', abdstatgetter('count-literal'), None),
                ('candidates', abdstatgetter('candidates-evaluated'), None),
                ('pruned candidates', abdstatgetter('candidates-pruned'), None),
                ('binsec calls', abdstatgetter('count-binsec-call'), None),
                ('restarts', abdstatgetter('count-restart'), None),
        ]
        telements = [
                ('#', lambda b, m, md: 1, None),
                ('total binsec time', abdstatgetter('times-binsec', fun=lambda b, m, md, d: sum(d)), None),
                ('first solution', abdstatgetter('time-first-solution'), None),
                ('last solution', abdstatgetter('time-last-solution'), None),
                ('total-time', lambda b, m, md: md['abducer']['time'] if 'abducer' in md else 0, None),
        ]
        ctable = self.get_table(celements)
        ttable = self.get_table(telements)
        caggregators = { k : sum for k in (e[0] for e in celements) }
        taggregators = { k : sum for k in (e[0] for e in telements if not e[0].endswith('%')) }
        # TODO: Fix: taggregators.update({ k : (lambda l: 100*statistics.mean(l)) for k in (e[0] for e in telements if e[0].endswith('%')) })
        cformatters = { k : None for k in (e[0] for e in celements) }
        tformatters = { k : (lambda v: datetime.timedelta(seconds=round(v))) for k in (e[0] for e in telements if not e[0].endswith('%')) }
        # TODO: Fix: tformatters.update({ k : (lambda v: round(v, 1)) for k in (e[0] for e in telements if e[0].endswith('%')) })
        tformatters['#'] = None
        owner = lambda optl : lambda m : optl in m[0].ctx['source'] and 'abducer' in m[0].ctx.mutants[m[1]]
        ownerships = [ owner(optl) for optl in ('O0', 'O1', 'O2', 'O3', 'Os') ]
        ownerships.append(lambda m : 'abducer' in m[0].ctx.mutants[m[1]])
        ccategories = [ (o, caggregators, cformatters) for o in ownerships ]
        tcategories = [ (o, taggregators, tformatters) for o in ownerships ]
        catable = self.aggregate_table(ctable, ccategories)
        tatable = self.aggregate_table(ttable, tcategories)
        firstcols = [ 'O0', 'O1', 'O2', 'O3', 'Os', 'total' ]
        pp.print_pretty_table(catable, sys.stdout, aslist=True, bdr=self.ctx['opt.rpp-bdr'], use_maxlen=False, split=True, firstcol=firstcols, withtotal=False)
        pp.print_pretty_table(tatable, sys.stdout, aslist=True, bdr=self.ctx['opt.rpp-bdr'], use_maxlen=False, split=True, firstcol=firstcols, withtotal=False)
        self.log.info('printing meaned abduction insight tables')
        for key in catable:
            if key not in ('#', ''):
                for i in range(len(catable['#'])):
                    if catable[key][i] != 'no value' and catable['#'][i] != 'no value':
                        catable[key][i] = round(catable[key][i]/catable['#'][i], 0)
                    else:
                        catable[key][i] = 'no value'
        pp.print_pretty_table(catable, sys.stdout, aslist=True, bdr=self.ctx['opt.rpp-bdr'], use_maxlen=False, split=True, firstcol=firstcols, withtotal=False)
# --------------------
class SeaticMetaEngine:

    def __init__(self, ctx, metactx, logger):
        self.ctx = ctx
        self.metactx = metactx
        self.log = logger
        self.tasks = []

    def generate_tasks(self):
        self.tasks.append(ResultsComparatorMDT(self.ctx, self.metactx, self.log))

    def run(self):
        self.log.debug('starting meta engine tasks')
        for task in self.tasks:
            task.execute()

    def flush_tasklist(self):
        self.tasks.clear()
# --------------------
class SeaticMetaRunner(SeaticBaseRunner):

    def __init__(self, args, **kwargs):
        super().__init__(args, **kwargs)
        self.metactx = {}
        self._load_metactx(args.meta_context)
        self.tm = SeaticMetaEngine(self.ctx, self.metactx, self.log)

    def _load_metactx(self, mctxl):
        self.log.info('loading meta-contexts...')
        self.log.set_debug_cover(3)
        self.metactx = dict()
        for mctx in self.log.progress(mctxl):
            self.metactx[mctx] = ContextLoader(self.log, mctx).ctx
            if not 'mutants' in self.metactx[mctx].data:
                self.log.error('no analysis found in meta-context: {}'.format(mctx))
                self.metactx.pop(mctx)
        self.log.set_debug_cover(5)

    def run(self):
        self.tm.generate_tasks()
        self.tm.run()
# --------------------
