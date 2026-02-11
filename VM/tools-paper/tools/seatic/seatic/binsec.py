# --------------------
import os
import re
import io
from .core import Task, SystemTask
from pulseutils import logging as log
# --------------------
class BinsecLogChunk:

    def __init__(self, bswitch, level, data):
        self.bswitch = bswitch
        self.level = level
        self.data = data
# --------------------
class BinsecLogParser:

    def __init__(self, data, logger, robust=False):
        self.logger = logger
        self.robust = robust

        self.logdata = []
        self.models = []
        self._last_smt = None
        self._last_model = None

        self.status = {
            'goal-unreachable': False,
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

    def _parse_fml_chunk(self, chunk):
        if chunk.data.startswith('Will open'):
            self._handle_smt_source(chunk)

    def _handle_smt_source(self, chunk):
        self._last_smt = chunk.data.replace('Will open ', '')
        if not os.path.isfile(self._last_smt):
            self.logger.warning('recovering unlogged smtfile: {}'.format(self._last_smt))

    def _handle_sse_directive(self, chunk):
        self._detect_sse_enumerate(chunk)

    def _detect_sse_enumerate(self, chunk):
        hookl = r'enumerate\s+possible values \(([0-9]+)\)'
        hookv = r'\{([0-9]+); ([0-9]+)\}'

        lmatch = re.search(hookl, chunk.data)
        if lmatch is not None:
            vcount = int(lmatch[1])
            if vcount > 0:
                values = []
                for vmatch in re.finditer(hookv, chunk.data):
                    values.append((int(vmatch[1]), int(vmatch[2])))
                if len(values) != vcount:
                    log.warning('recovering {} enumeration value while expecting {}'.format(len(values), vcount))
                self.logger.debug('recovered enumeration values: {}'.format(values))
                if self._last_model is not None:
                    self._last_model['enum'] = values
                else:
                    self.logger.warning('recovered out of context enumeration value')

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
        result = dict()
        for modell in model.split('\n'):
            if ':' in modell:
                ldata = [s.strip() for s in modell.split(':')]
                if len(ldata) > 2:
                    self.logger.warning('multi-colon model var (unhandled): {}'.format(modell))
                result[ldata[0]] = ldata[1]
        self.logger.debug('model recovered: {}'.format(result))
        return result
# --------------------
class BinsecAnalysisTask(SystemTask):

    def __init__(self, ctx, mutant, mutant_data, logger, ccl='binsec'):
        cmd = [ctx['tool'][ccl], '-file', mutant, '-config', ctx['config'][ccl], '-sse-memory', ctx['config.{}-memory'.format(ccl)]]
        if ctx['opt.logsmt']:
            cmd += ['-sse-smt-dir', ctx.mutant_logtarget(mutant, '{}-smt'.format(ccl), 'smtlog')]
        super().__init__(cmd, logger, timeout=ctx['timeout'][ccl], log_errors=False)
        self.ctx = ctx
        self.ccl = ccl
        self.mutant = mutant
        self.data = mutant_data
        self.robust = ccl == 'binsec-robust'

    def should_run(self):
        return True

    def should_discard(self):
        return False

    def _preprocess(self):
        target_dir = self.ctx.mutant_logtarget(self.mutant, '{}-smt'.format(self.ccl), 'smtlog')
        if self.ctx['opt.logsmt'] and not os.path.isdir(target_dir):
            os.makedirs(target_dir)

    def _postprocess(self):
        logfile = self.ctx.mutant_logtarget(self.mutant, self.ccl)
        if self.ctx['opt.task_logging']:
            self._log_output(logfile)
        self.data[self.ccl] = {'time': self.cmd_result.time, 'timeout': self.cmd_result.timeout, 'returncode': self.cmd_result.returncode}

        parser = BinsecLogParser(self.output, self.log, self.robust)

        target = self.data[self.ccl]
        target['vulnerable'] = len(parser.models) > 0
        target['status'] = parser.status
        target['models'] = parser.models
        if target['vulnerable']:
            self.log.debug('vulnerability found in mutant {2} (reach {0:#0{1}x})'.format(self.ctx['oracle.reach'], 8+2, self.mutant))
# --------------------
class BinsecRobustAnalysisTask(BinsecAnalysisTask):

    def __init__(self, ctx, mutant, mutant_data, logger):
        super().__init__(ctx, mutant, mutant_data, logger, ccl='binsec-robust')

    def should_run(self):
        return self.ctx.is_vulnerable(self.mutant, self.data)
# --------------------
