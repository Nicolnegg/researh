# --------------------
import os
import enum
import shutil
from datetime import datetime
import yaml
try:
    from yaml import CLoader as ymlLoader, CDumper as ymlDumper
except ImportError:
    from yaml import Loader as ymlLoader, Dumper as ymlDumper
from pulseutils.logging import Logger
from . import cfggen
from .core import SeaticContext
from .binary import GetSourceInfoTask
from .analysis import FullAnalysisTask
from .results import ExportResultsTask
# --------------------
class SeaticAction(enum.Enum):
    Prepare                     = 'prepare'
    Analysis                    = 'mutation'
    ExportResults               = 'export'
# --------------------
def seatic_action(s):
    for action in list(SeaticAction):
        if s in (action.name, action.value):
            return action
    return None
# --------------------
def separate_action_list(l):
    curr = []
    for a in l:
        curr.append(a)
        if a == SeaticAction.Prepare:
            yield curr
            curr = []
    yield curr
# --------------------
DEFAULT_ACTION_LIST = (SeaticAction.Prepare, SeaticAction.Analysis, SeaticAction.ExportResults)
# --------------------
class SeaticEngine:

    def __init__(self, ctx, logger):
        self.log = logger
        self.log.debug('init task manager')
        self.ctx = ctx
        self.tasks = []

    def generate_tasks_from(self, tasklist):
        for t in tasklist:
            self.generate_tasks(t)

    def generate_tasks(self, task):
        self.log.debug('generate tasks for token {}'.format(task))
        {
            SeaticAction.Prepare : self.generate_tasks_prepare,
            SeaticAction.Analysis : self.generate_tasks_analysis,
            SeaticAction.ExportResults : self.generate_tasks_exportresults,
        }[task]()

    def generate_tasks_prepare(self):
        self.tasks.append(GetSourceInfoTask(self.ctx, self.log))

    def generate_tasks_analysis(self):
        self.tasks.append(FullAnalysisTask(self.ctx, self.log))

    def generate_tasks_exportresults(self):
        self.tasks.append(ExportResultsTask(self.ctx, self.log))

    def run(self):
        self.log.debug('starting task manager tasks')
        while self.tasks:
            self.tasks.pop(0).execute()

    def flush_tasklist(self):
        self.tasks.clear()
# --------------------
class SeaticMergedEngine(SeaticEngine):

    def __init__(self, ctxs, logger):
        self.log = logger
        self.log.debug('init merged task manager')
        self.ctxs = ctxs
        self.tasks = []

    def generate_tasks_prepare(self):
        for ctx in self.ctxs:
            self.tasks.append(GetSourceInfoTask(ctx, self.log))

    def generate_tasks_analysis(self):
        self.tasks.append(FullAnalysisTask(self.ctxs, self.log, merged=True))

    def generate_tasks_exportresults(self):
        for ctx in self.ctxs:
            self.tasks.append(ExportResultsTask(ctx, self.log))
# --------------------
class ContextLoader:

    def __init__(self, logger, ctxfile=None, ctx=None, args=None):
        self.log = logger
        self.log.debug('initializing context')
        self.ctx = SeaticContext(self.log) if ctx is None else ctx
        if ctxfile is not None:
            self._update_ctx(ctxfile)
        if args is not None:
            for arg in vars(args):
                self.ctx['opt'][arg] = getattr(args, arg)

    def _update_ctx(self, ctxfile):
        self.log.info('loading context from {}'.format(ctxfile))
        stream = open(ctxfile, 'r')
        try:
            ldata = yaml.load(stream, Loader=ymlLoader)
            self.ctx.update_from(ldata)
        except yaml.YAMLError as e:
            if hasattr(e, 'problem_mark'):
                mark = e.problem_mark
                msg = 'yaml loading error: {} @{}:{}'.format(e, mark.line+1, mark.column+1)
                self.log.critical(msg)
                raise Exception(msg)
            else:
                self.log.critical(str(e))
                raise e
        stream.close()
# --------------------
class SeaticBaseRunner:

    def __init__(self, args, **kwargs):
        self.log = Logger(level=4 if args.debug else 3,
                          color=args.color,
                          log_progress=args.progress and not args.debug)
        self.log.debug('initializing Seatic Core')
        self.args = args
        self.ctx = ContextLoader(self.log, args.context_file, args=args).ctx
        self.ctx.update_fargs(args)

    def __del__(self):
        timestamp = datetime.now().strftime('%Y-%m-%d.%H-%M-%S.%f')
        logfile = 'seatic.{}.yml'.format(timestamp)
        data = self.ctx.data
        self.log.info('dumping context to {}'.format(logfile))
        with open(logfile, 'w') as stream:
            yaml.dump(data, stream, Dumper=ymlDumper)

    def run(self):
        if self.args.tempdir_cleanup:
            tmpdir = self.ctx['environ.TMPDIR']
            self.log.info('cleaning up temporary nix dirs in {}'.format(tmpdir))
            if os.path.isdir(tmpdir):
                for tmpdata in self.log.progress(os.listdir(tmpdir)):
                    shutil.rmtree(os.path.join(tmpdir, tmpdata))
            else:
                self.log.debug('nothing to do')
# --------------------
class SeaticBaseMergedRunner:

    def __init__(self, args, **kwargs):
        self.log = Logger(level=4 if args.debug else 3,
                          color=args.color,
                          log_progress=args.progress and not args.debug)
        self.log.debug('initializing merged Seatic Core')
        self.args = args
        self.ctxs = { context_file: ContextLoader(self.log, context_file, args=args).ctx for context_file in args.meta_context }
        for ctxif, ctx in self.ctxs.items():
            ctx.update_fargs(args)

    def __del__(self):
        timestamp = datetime.now().strftime('%Y-%m-%d.%H-%M-%S.%f')
        for ctxif, ctx in self.ctxs.items():
            logfile = os.path.join(os.path.dirname(ctxif), 'seatic.{}.yml'.format(timestamp))
            data = ctx.data
            self.log.info('dumping {}-imported context to {}'.format(ctxif, logfile))
            with open(logfile, 'w') as stream:
                yaml.dump(data, stream, Dumper=ymlDumper)

    def run(self):
        if self.args.tempdir_cleanup:
            for ctxif, ctx in self.ctxs.items():
                tmpdir = ctx['environ.TMPDIR']
                self.log.info('cleaning up temporary nix dirs in {}'.format(tmpdir))
                if os.path.isdir(tmpdir):
                    for tmpdata in self.log.progress(os.listdir(tmpdir)):
                        shutil.rmtree(os.path.join(tmpdir, tmpdata))
                else:
                    self.log.debug('nothing to do')
# --------------------
class SeaticRunner(SeaticBaseRunner):

    def __init__(self, args, **kwargs):
        super().__init__(args, **kwargs)
        self.tm = SeaticEngine(self.ctx, logger=self.log)
        self.actions = kwargs['actions'] if 'actions' in kwargs else DEFAULT_ACTION_LIST

    def run(self):
        self.log.info('running Seatic...')
        for al in separate_action_list(self.actions):
            self.tm.generate_tasks_from(al)
            self.tm.run()
            self.tm.flush_tasklist()
        super().run()
# --------------------
class SeaticMergedRunner(SeaticBaseMergedRunner):

    def __init__(self, args, **kwargs):
        super().__init__(args, **kwargs)
        self.tm = SeaticMergedEngine(list(self.ctxs.values()), logger=self.log)
        self.actions = kwargs['actions'] if 'actions' in kwargs else DEFAULT_ACTION_LIST

    def run(self):
        self.log.info('running Seatic (merged)...')
        for al in separate_action_list(self.actions):
            self.tm.generate_tasks_from(al)
            self.tm.run()
            self.tm.flush_tasklist()
        super().run()
# --------------------
class ConfigGeneratorRunner(SeaticBaseRunner):

    def __init__(self, args, **kwargs):
        super().__init__(args, **kwargs)
        binary_file = args.binary_file if args.binary_file is not None else self.ctx['source']
        self.log.info('generating configuration for binary: {}'.format(binary_file))
        self.cg = cfggen.get_configurator(args.configurator, self.ctx, binary_file, args.output_dir, self.log)

    def run(self):
        self.log.info('running Seatic configuration generator...')
        self.cg.run()
        super().run()
# --------------------
class SeaticAutoRunner(ConfigGeneratorRunner, SeaticRunner):

    def __init__(self, args, **kwargs):
        super().__init__(args, **kwargs)

    def run(self):
        super().run()
# --------------------
# --------------------
