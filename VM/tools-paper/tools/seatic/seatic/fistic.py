# --------------------
import os
import re
import io
from .core import Task, SystemTask
from pulseutils.files import prefixate
from pulseutils import logging as log
# --------------------
# --------------------
def detect_mutants(ctx, logger):
    generated_dir = ctx['mutation.outdir']
    generated = os.listdir(generated_dir)
    new_mutants = { os.path.join(generated_dir, mutant) : dict() for mutant in generated }
    for nmutant, nmdata in new_mutants.items():
        if not nmutant in ctx['mutants']:
            ctx['mutants'][nmutant] = nmdata
    logger.info('generated mutant count: {}'.format(len(new_mutants)))
# --------------------
class AutodetectMutantsTask(Task):

    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx

    def _execute(self):
        log.info('auto-detecting mutants...')
        super()._execute()

    def _postprocess(self):
        detect_mutants(self.ctx)
# --------------------
class FisticMutationTask(SystemTask):

    def __init__(self, ctx, logger, detect=True, prefix=None):
        cmd  = [ctx['tool.fistic'], '-b', prefixate(ctx['source'], prefix)]
        cmd += ['-e', 'none', '--no-color', '--no-progress']
        cmd += ['--fault-model', 'skip', '-n', str(ctx['mutation.cpt'])]
        cmd += ['-t', '{:x}'.format(ctx['source-info.text-offset'])]
        cmd += ['--faulted-binaries-dir', prefixate(ctx['mutation.outdir'], prefix)]
        cmd += ['--function'] + ctx['mutation.targets']
        super().__init__(cmd, logger)
        self.ctx = ctx
        self.detect = detect
        self.prefix = prefix

    def _execute(self):
        self.log.info('generating binary mutants')
        super()._execute()

    def _postprocess(self):
        logfile = os.path.join(self.ctx['log.fistic'], 'faulter.log')
        if self.prefix is not None:
            logfile = prefixate(logfile, self.prefix)
        # Logging
        if self.ctx['opt.task_logging'] and self.cmd_result is not None:
            self._log_output(logfile)
        if self.detect:
            # Detecting mutants
            detect_mutants(self.ctx, self.log)
# --------------------
class FisticSimulationTask(SystemTask):

    def __init__(self, ctx, mutant, mutant_data, logger):
        cmd  = [ctx['tool']['fistic'], '-b', mutant]
        cmd += ['--fault-model', 'none', '--placer', 'none']
        cmd += ['-e', 'qemu', '--no-color', '--no-progress']
        # TODO: recover golden timeout/results and 1. use this timeout, 2. compare result
        super().__init__(cmd, logger)
        self.ctx = ctx
        self.mutant = mutant
        self.data = mutant_data

    def should_run(self):
        return True

    def should_discard(self):
        return False

    def _postprocess(self):
        self._recover_result()
        if self.ctx['opt.task_logging'] and self.cmd_result is not None:
            logfile = os.path.join(self.ctx['log.fistic'], '{}.fistic.log'.format(os.path.basename(self.mutant)))
            self._log_output(logfile)

    def _recover_result(self):
        parser = FisticLogParser(self.output, self.log)
        bname = os.path.basename(self.mutant)
        self.data['simulation'] = {'data': parser.results['golden'],
                                   'time': self.cmd_result.time,
                                   'timeout': self.cmd_result.timeout,
                                   'returncode': self.cmd_result.returncode}
# --------------------
class LegacyFisticLogParser:

    def __init__(self, data, logger):
        self.log = logger
        self.results = {}
        self.current_m = None
        self.current_s = dict(result=None, crash=False, timeout=False)

        self._parse(data)

    def _push_result(self):
        self.results[self.current_m] = self.current_s
        self.current_m = None
        self.current_s = dict(result=None, crash=False, timeout=False)

    def _update(self, line):
        if re.match(r'\[[0-9]+\]', line) or line.startswith('==VERDICT=='):
            self._push_result()
        elif line.startswith('Setting'):
            self.current_m = os.path.basename(line.split()[1])
        elif line.startswith('b'):
            if '==VERDICT== OK' in line:
                self.current_s['result'] = False
            elif '==VERDICT== FAIL' in line:
                self.current_s['result'] = True
            else:
                self.current_s['crash'] = True
        elif line.strip() == 'None':
            self.current_s['timeout'] = True

    def _parse(self, data):
        self.log.debug('parsing fistic log')
        with io.StringIO(data) as stream:
            for line in stream:
                self._update(line)
# --------------------
class FisticLogParser(LegacyFisticLogParser):

    def _push_result(self, res):
        self.results['golden'] = dict(result=None, crash=False, timeout=False)
        if res == 'timeout':
            self.results['golden']['timeout'] = True
        if res == 'failure':
            self.results['golden']['crash'] = True
        if res == 'valid':
            self.results['golden']['result'] = False
        if res == 'invalid':
            self.results['golden']['result'] = True

    def _update(self, line):
        if re.match(r'\[info\]   : golden run evaluation result:', line):
            self._push_result(line.split(':')[2].strip())
# --------------------
# --------------------
