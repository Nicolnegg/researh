# --------------------
import concurrent.futures
import itertools
import copy
from .core import Task
from .binary import AssCodeGenerationTask, GetMutantInfoTask
from .binsec import BinsecAnalysisTask, BinsecRobustAnalysisTask
from .fistic import FisticMutationTask, FisticSimulationTask
from .abduction import AbductionAnalysisTask, SeverityEvaluationTask
from .simulation import ConstraintValidationTask, LogConstraintValidationTask, GenerateSimulationScriptTask
from pulseutils.logging import ParallelStatusesLogger, TaskStatus
# --------------------
class FullAnalysisTask(Task):
    
    def __init__(self, ctx, logger, merged=False):
        super().__init__(logger)
        self.ctxs = ctx if merged else [ ctx ]
        self.subtasks = {}

    def _detect_mutants(self):
        for ctx in self.ctxs:
            FisticMutationTask(ctx, self.log).execute()
            if ctx['opt.vsimulation'] or ctx['opt.prepare_vsimulation']:
                FisticMutationTask(ctx, self.log, detect=False, prefix=ctx['target.vsimulation-prefix']).execute()

    def _global_analysis(self):
        for ctx in self.ctxs:
            if ctx['opt.prepare_vsimulation']:
                GenerateSimulationScriptTask(ctx, self.log).execute()

    def _generate_analyses(self):
        for ctx in self.ctxs:
            analyzers = [GetMutantInfoTask]
            if ctx['opt.simulation']:
                analyzers.append(FisticSimulationTask)
            if ctx['opt.binsec']:
                analyzers.append(BinsecAnalysisTask)
            if ctx['opt.robust']:
                analyzers.append(BinsecRobustAnalysisTask)
            if ctx['opt.abduction']:
                analyzers.append(AbductionAnalysisTask)
                analyzers.append(SeverityEvaluationTask)
            if ctx['opt.vsimulation']:
                if ctx['opt.logged_vsimulation']:
                    analyzers.append(LogConstraintValidationTask)
                else:
                    analyzers.append(ConstraintValidationTask)
            for mutant, mdata in ctx.mutants.items():
                if ctx['opt.only_following_mutants']:
                    pflag = True
                    for mcore in ctx['opt.only_following_mutants']:
                        if mcore in mutant:
                            pflag = False
                            break
                    if pflag:
                        continue
                mwdata = copy.deepcopy(mdata)
                manalysis = MutantAnalysisTask(ctx, mutant, self.log, analyzers, mwdata)
                self.subtasks[ctx, mutant] = manalysis
        return analyzers

    def _execute_parallel(self, analyzers, workers):
        if self.log.log_progress:
            self.log.capture()
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            tp = ( executor.submit(subtask.execute) for subtask in self.subtasks.values() )
            if self.log.log_progress:
                plogger = ParallelStatusesLogger(self.subtasks.values(), 'Analyzing mutants (merged)',
                                                 [ a.__name__ for a in analyzers ])
                tp = itertools.chain([executor.submit(plogger.start)], tp)
            for tres in concurrent.futures.as_completed(tp):
                tres.result()
        if self.log.log_progress:
            self.log.uncapture()

    def _execute(self):
        self._detect_mutants()
        analyzers = self._generate_analyses()
        self.log.info('analyzing mutants')
        if self.ctxs[0]['opt.parallel']:
            self._execute_parallel(analyzers, self.ctxs[0]['opt.parallel_workers'])
        else:
            for subtask in self.log.progress(self.subtasks.values()):
                subtask.execute()
        self._global_analysis()

    def _postprocess(self):
        results = {}
        for (ctx, mutant), task in self.subtasks.items():
            if not ctx in results:
                results[ctx] = {}
            if not task.to_discard:
                results[ctx][mutant] = task.get_results()
        for ctx, mdata in results.items():
            ctx['mutants'] = mdata
# --------------------
class MutantAnalysisTask(Task):

    def __init__(self, ctx, mutant, logger, analyzers, mdata=None):
        super().__init__(logger)
        self.ctx = ctx
        self.mutant = mutant
        self.analyzers = analyzers
        self.runner = None
        self.to_discard = False
        self.mdata = {} if mdata is None else mdata

    def get_id(self):
        return self.mutant

    def get_state(self):
        if self.finished:
            return TaskStatus.Completed, None
        if not self.started:
            return TaskStatus.Pending, None
        return TaskStatus.Running, self.runner.__class__.__name__

    def get_results(self):
        return self.mdata

    def _execute(self):
        for analyzer in self.analyzers:
            self.runner = analyzer(self.ctx, self.mutant, self.mdata, self.log)
            if self.runner.should_run():
                self.runner.execute()
            if self.runner.should_discard():
                self.to_discard = True
                break
# --------------------
# --------------------
