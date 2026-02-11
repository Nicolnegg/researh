# --------------------
import os
import re
import io
import zipfile
import datetime
import locale
from .core import Task, SystemTask
from pulseutils.files import prefixate
from .abduction import format_constraints
from pulseutils import logging as log
# --------------------
class ConstraintValidationTask(SystemTask):

    def __init__(self, ctx, mutant, mutant_data, logger):
        cmd  = [ ctx['tool.qemu'], '-machine', 'lm3s6965evb', '-cpu', 'cortex-m3', '-nographic' ]
        cmd += [ '-monitor', 'null', '-serial', 'null', '-semihosting' ]
        cmd += [ '-kernel', prefixate(mutant, ctx['target.vsimulation-prefix'], 1)]
        cmd += [ '2>&1', '|', ctx['config.vsimulation-script'], '-s' ]
        try:
            cmd += [ '-c', format_constraints(mutant_data['abducer']['constraints']) ]
        except KeyError:
            cmd += [ '-c', 'False' ]
        super().__init__(' '.join(cmd), logger, timeout=ctx['timeout.vsimulation'], log_errors=False, shell=True)
        self.ctx = ctx
        self.mutant = mutant
        self.data = mutant_data

    def should_run(self):
        return True

    def should_discard(self):
        return False

    def _preprocess(self):
        if self.ctx['opt.task_logging'] and not os.path.isdir(self.ctx['log.vsimulation']):
            os.makedirs(self.ctx['log.vsimulation'], exist_ok=True)

    def _postprocess(self):
        logfile = self.ctx.mutant_logtarget(self.mutant, 'vsimulation')
        if self.ctx['opt.task_logging']:
            self._log_output(logfile)
        self.data['vsimulation'] = {'time': self.cmd_result.time, 'timeout': self.cmd_result.timeout, 'returncode': self.cmd_result.returncode}
        if self.cmd_result.returncode == 0:
            target = self.data['vsimulation']
            elems = self.output.strip().split(';')
            elems = [ e.split(':') for e in elems ]
            elems = { k : int(v) for k, v in elems }
            target['matches'] = { True: elems['match'],
                                  False: elems['nomatch'],
                                  'vulnerabilities': elems['vulns'],
                                  'symbolic-vulnerabilities': elems['symbvulns'],
                                  'pessimistic-symbolic-vulnerabilities': elems['symbvulnps'],
                                  'missed-vulnerabilities': elems['missedpos'],
                                  'wrong-vulnerabilities': elems['missedneg']}
# --------------------
class LogConstraintValidationTask(ConstraintValidationTask):

    AUTO_TIMEOUT_THRESHOLD = 10

    def __init__(self, ctx, mutant, mutant_data, logger):
        zipfile = os.path.join(ctx['target.vsimulation-logs'], os.path.basename(mutant).replace('.bin', '.zip'))
        timefile = '{}.time.log'.format(zipfile)
        if ctx['opt.vsimulation_estimate']:
            cmd  = [ ctx['config.vsimulation-script'], '-t', '-l', zipfile, '--decompress' ]
        else:
            cmd  = [ ctx['config.vsimulation-script'], '-s', '-l', zipfile, '--decompress' ]
        try:
            cmd += [ '-c', format_constraints(mutant_data['abducer']['constraints'], quotes=False) ]
        except KeyError:
            cmd += [ '-c', 'False' ]
        SystemTask.__init__(self, cmd, logger, timeout=ctx['timeout.vsimulation'], log_errors=False, shell=False)
        self.ctx = ctx
        self.mutant = mutant
        self.data = mutant_data
        self.zipfile = zipfile
        self.timefile = timefile

    def _parse_date(self, date, retry=True):
        try:
            return datetime.datetime.strptime(date, '%c').timestamp()
        except ValueError as err:
            pass
        try:
            return datetime.datetime.strptime(date.replace(' CEST', ''), '%a %d %b %Y %X').timestamp()
        except ValueError as err:
            if not retry:
                self.log.warning('failed to parse datetime data: {}: {}'.format(date, err))
                return 0
        self.log.debug('trying relocalisation of datetime data: {}'.format(date))
        safelocale = locale.getlocale(locale.LC_TIME)
        locale.setlocale(locale.LC_TIME, ('fr_FR', 'UTF-8'))
        data = self._parse_date(date, retry=False)
        locale.setlocale(locale.LC_TIME, safelocale)
        return data

    def _preprocess(self):
        super()._preprocess()
        if not os.path.isdir(self.ctx['target.vsimulation-locals']):
            os.makedirs(self.ctx['target.vsimulation-locals'], exist_ok=True)
        self.log.debug('loading zip-file: {}'.format(self.zipfile))

    def _postprocess(self):
        super()._postprocess()
        target = self.data['vsimulation']
        target['analysis'] = dict(time=target['time'], timeout=target['timeout'], returncode=target['returncode'])
        try:
            with open(self.timefile) as stream:
                data = stream.readlines()
            start, stop = data[0].strip(), data[1].strip()
            start, stop = self._parse_date(start), self._parse_date(stop)
            target['time'] = stop - start
            target['auto-timeout'] = start == stop or target['time'] <= self.AUTO_TIMEOUT_THRESHOLD
            target['timeout'] = target['auto-timeout'] or target['time'] > self.ctx['timeout.vsimulation']
            target['returncode'] = 0
        except FileNotFoundError as err:
            self.log.error('could not fild mutant vsimulation time file @{}'.format(self.timefile))
            target['time'] = 0
            target['auto-timeout'] = False
            target['timeout'] = False
            target['returncode'] = -1
# --------------------
class GenerateSimulationScriptTask(Task):

    def __init__(self, ctx, logger):
        super().__init__(logger)
        self.ctx = ctx
        self.sourcelist = { None: [] }

    def _preprocess(self):
        directory = os.path.dirname(self.ctx['target.vsimulation-cmakefile'])
        if directory != '' and not os.path.isdir(directory):
            os.makedirs(directory)
        if self.ctx['opt.vsimulation_list'] is not None:
            self._build_sourcelist(self.ctx['opt.vsimulation_list'])

    def _build_sourcelist(self, listfile):
        with open(listfile) as stream:
            for rline in stream:
                line = rline.strip()
                if line == '':
                    continue
                if ':' in line:
                    parts = line.split(':')
                    source, mutant = parts[0], ':'.join(parts[1:])
                    if not source in self.sourcelist:
                        self.sourcelist[source] = []
                    self.sourcelist[source].append(mutant)
                else:
                    self.sourcelist[None].append(line)

    def _in_sourcelist(self, mutant):
        return mutant in self.sourcelist[None] or mutant in self.sourcelist[self.ctx['source']]

    def _list_mutants(self):
        for mutant in self.ctx.mutants:
            if self.ctx['opt.vsimulation_list'] is None or self._in_sourcelist(mutant):
                yield mutant

    def _execute(self):
        cmakefile = self.ctx['target.vsimulation-cmakefile']
        self.log.info('generating vsimulation cmakefile: {}'.format(cmakefile))
        with open(cmakefile, 'w') as stream:
            for mutant in self._list_mutants():
                vsmutant = prefixate(mutant, self.ctx['target.vsimulation-prefix'], 1)
                vsmutant_core = os.path.splitext(vsmutant)[0]
                vsmutant_target = os.path.join(self.ctx['source'], vsmutant).replace('/', '-')
                vsmutant_src = os.path.join('${CMAKE_CURRENT_SOURCE_DIR}', vsmutant)
                vsmutant_log = os.path.join('${CMAKE_CURRENT_BINARY_DIR}', '{}.log'.format(vsmutant_core))
                vsmutant_zip = os.path.join('${CMAKE_CURRENT_BINARY_DIR}', '{}.zip'.format(vsmutant_core))
                stream.write('add_custom_command(COMMAND {}/{} {} {}'.format('${CMAKE_CURRENT_SOURCE_DIR}', self.ctx['config.vsimulation-wrap-script'], vsmutant_src, vsmutant_zip))
                stream.write(' DEPENDS {} OUTPUT {})\n'.format(vsmutant_src, vsmutant_zip))
                stream.write('add_custom_target({} ALL DEPENDS {})\n'.format(vsmutant_target, vsmutant_zip))
# --------------------
