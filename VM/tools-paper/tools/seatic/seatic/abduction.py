# --------------------
import os
import re
import io
import zipfile
from .core import Task, SystemTask
from pulseutils import logging as log
# --------------------
class AbducerLogParser:

    KnownStats = (
        ('number of solutions',           'count-solution'),
        ('number of unsolutions',         'count-unsolution'),
        ('number of examples',            'count-example'),
        ('number of counter-examples',    'count-counterex'),
        ('number of necessary literals',  'count-necessary'),
        (' binsec calls',                 'count-binsec-call'),
        (' binsec timeouts',              'count-binsec-timeout'),
        (' binsec crashes',               'count-binsec-crash'),
        (' binsec times',                 'times-binsec'),
        ('minibinsec calls',              'count-minibinsec-call'),
        ('binsec-unsat-consistent calls', 'count-binsec-consistency-call'),
        ('constant-test calls',           'count-constant-test-call'),
        ('number of restarts',            'count-restart'),
        ('number of variables',           'count-variable'),
        ('number of literals',            'count-literal'),
        ('evaluated candidates',          'candidates-evaluated'),
        ('considered candidates',         'candidates-considered'),
        ('pruned candidates',             'candidates-pruned'),
        ('counterex-pruned candidates',   'candidates-pruned-counterex'),
        ('consistency-pruned candidates', 'candidates-pruned-consistency'),
        ('solution-pruned candidates',    'candidates-pruned-solution'),
        ('unsolution-pruned candidates',  'candidates-pruned-unsolution'),
        ('necessary-pruned candidates',   'candidates-pruned-necessary'),
        ('first solution',                'time-first-solution'),
        ('last  solution',                'time-last-solution'),
        ('first unsolution',              'time-first-unsolution'),
        ('last  unsolution',              'time-last-unsolution'),
        ('first counterex',               'time-first-counterex'),
        ('last  counterex',               'time-last-counterex'),
        ('first example',                 'time-first-example'),
        ('last  example',                 'time-last-example'),
        ('first necessaryc',              'time-first-necessary'),
        ('last  necessaryc',              'time-last-necessary'),
    )

    def __init__(self, data, logger):
        self.log = logger
        self.constraints = []
        self.necessary = []
        self.exact = False
        self.stats = dict()
        self._parse(data)

    def _parse(self, data):
        with io.StringIO(data) as stream:
            for line in stream:
                if 'satisfying solution' in line:
                    constraint = eval(':'.join(line.split(':')[2:]).strip())
                    self.constraints.append(constraint)
                if 'updated sufficient condition' in line or 'nas condition' in line:
                    self.constraints = eval(':'.join(line.split(':')[2:]).strip())
                if 'nas condition' in line:
                    self.exact = True
                if 'necessary constraint' in line:
                    constraint = eval(':'.join(line.split(':')[2:]).strip())
                    self.necessary.append(constraint)
                for hook, stat in self.KnownStats:
                    if hook in line:
                        value = eval(line.split(':')[-1].strip())
                        self.stats[stat] = value
# --------------------
class AbductionAnalysisTask(SystemTask):

    def __init__(self, ctx, mutant, mutant_data, logger):
        cmd  = [ ctx['tool.abducer'], '--no-color', '--no-progress' ]
        cmd += [ '--binsec-config', ctx['config.abducer-binsec-config'] ]
        cmd += [ '--binsec-directives', ctx['config.abducer-directives'] ]
        cmd += [ '--binsec-binary', mutant ]
        cmd += [ '--binsec-addr', '0x{:x}'.format(ctx['abduction.address']) ]
        cmd += [ '--binsec-memory', ctx['config.abducer-binsec-memory'] ]
        cmd += [ '--binsec-timeout', str(ctx['timeout.binsec']) ]
        if ctx['opt.task_logging']:
            cmd += [ '--binsec-config-logdir', 'abducer.config.log' ]
        else:
            cmd += [ '--binsec-delete-configs' ]
        cmd += [ '--literals', ctx['config.abducer-literals'] ]
        cmd += [ '--max-depth', str(ctx['abduction.depth']) ]
        cmd += [ '--separate-bytes' ]
        cmd += [ '--binsec-robust', '--robust-config', ctx['config.abducer-robust-config'] ]
        if ctx['opt.with_abduction_inequalities']:
            cmd += [ '--with-inequalities' ]
        if ctx['opt.no_abduction_counterex']:
            cmd += [ '--no-prune-counterex' ]
        if ctx['opt.no_abduction_necessaryc']:
            cmd += [ '--no-prune-necessary', '--no-constant-detection' ]
        if ctx['opt.no_abduction_ordering']:
            cmd += [ '--no-literal-ordering' ]
        if ctx['opt.enforce_abducer_propagation']:
            cmd += [ '--input-variables-only' ]
            cmd += [ '--no-constant-detection' ]
        if ctx['opt.debug']:
            cmd += [ '--debug' ]
        super().__init__(cmd, logger, timeout=ctx['timeout.abducer'], log_errors=False, softkill=True)
        self.ctx = ctx
        self.mutant = mutant
        self.data = mutant_data

    def should_run(self):
        return self.ctx.is_vulnerable(self.mutant, self.data)

    def should_discard(self):
        return False

    def _preprocess(self):
        if self.ctx['opt.task_logging'] and not os.path.isdir(self.ctx['log.abducer']):
            os.makedirs(self.ctx['log.abducer'])

    def _postprocess(self):
        logfile = self.ctx.mutant_logtarget(self.mutant, 'abducer')
        if self.ctx['opt.task_logging']:
            self._log_output(logfile)
        self.data['abducer'] = {'time': self.cmd_result.time, 'timeout': self.cmd_result.timeout, 'returncode': self.cmd_result.returncode}
        parser = AbducerLogParser(self.output, self.log)
        target = self.data['abducer']
        target['constraints'] = parser.constraints
        target['necessary'] = parser.necessary
        target['exact'] = parser.exact
        target['statistics'] = parser.stats
        self.log.debug('constraints found in mutant {}: {}'.format(self.mutant, parser.constraints))
# --------------------
def format_constraints(constraints, quotes=True):
    if len(constraints) == 0:
        return 'False'
    strc = []
    for c in constraints:
        if len(c) == 0:
            strc.append('True')
        else:
            strc.append(';'.join(c))
    if quotes:
        return '"' + '/'.join(strc) + '"'
    return '/'.join(strc)
# --------------------
class SeverityEvaluationTask(SystemTask):

    def __init__(self, ctx, mutant, mutant_data, logger):
        cmd  = [ ctx['config.vsimulation-script'], '-e' ]
        try:
            cmd += [ '-c', format_constraints(mutant_data['abducer']['constraints'], quotes=False) ]
        except KeyError:
            cmd += [ '-c', 'False' ]
        super().__init__(cmd, logger, log_errors=False)
        self.ctx = ctx
        self.mutant = mutant
        self.data = mutant_data

    def should_run(self):
        return self.ctx.is_vulnerable(self.mutant, self.data)

    def should_discard(self):
        return False

    def _preprocess(self):
        if self.ctx['opt.task_logging'] and not os.path.isdir(self.ctx['log.severity']):
            os.makedirs(self.ctx['log.severity'])

    def _postprocess(self):
        logfile = self.ctx.mutant_logtarget(self.mutant, 'severity')
        if self.ctx['opt.task_logging']:
            self._log_output(logfile)
        self.data['severity-computation'] = {'time': self.cmd_result.time, 'timeout': self.cmd_result.timeout, 'returncode': self.cmd_result.returncode}
        if self.cmd_result.returncode == 0:
            results = self.output.strip().split(';')
            results = [ e.split(':') for e in results ]
            self.data['severity-computation']['tests'] = int(results[0][1])
            self.data['severity-computation']['value'] = int(results[1][1])
            self.data['severity-computation']['pessimistic'] = int(results[2][1])
# --------------------
