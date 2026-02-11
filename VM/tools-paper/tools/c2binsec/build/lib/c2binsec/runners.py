# ----------------------------------------
import sys
import os
import io
import time
from .core import TaskStatus, TaskException
from .utils import clog_reasons
from pulseutils.system import execute_command
# ----------------------------------------
# ----------------------------------------
class RunnerFiles:

    def __init__(self, filename, superdir=None, prefix=''):
        self.input = filename
        self.outdir = '{}.dir'.format(os.path.splitext(filename)[0])
        if superdir is not None:
            self.outdir = os.path.join(superdir, self.outdir)
        os.makedirs(self.outdir, exist_ok=True)
        corename = os.path.basename(os.path.splitext(filename)[0])
        self.runner = os.path.join(self.outdir, '{}.{}run.bash'.format(corename, prefix))
        self.blog   = os.path.join(self.outdir, '{}.{}binsec.log'.format(corename, prefix))
# ----------------------------------------
class BinsecTask:

    risks = {
        'unsupported' : 'unsupported',
        'Depth exceeded' : 'depth',
        'UNKNOWN' : 'unknown',
        'TIMEOUT' : 'solver-timeout',
        'warning' : 'warning',
        'Dynamic jump' : 'jump',
        'Uncaught exception' : 'exception',
        'Model' : 'model',
        'Goal unreachable' : 'unreachable',
    }

    def __init__(self, ifile, args, runner_prefix=''):
        self.files = RunnerFiles(ifile, args.output_dir, prefix=runner_prefix)
        self.args = args
        self.runner_prefix = runner_prefix
        self.debug_stack = []
        self.status = TaskStatus.Pending

    def _generate_command(self):
        return [ self.files.runner ]

    def __call__(self):
        try:
            self.status = TaskStatus.Running
            command = self._generate_command()
            self.debug_stack.append('run {}'.format(' '.join(command)))
            t_start = time.time()
            ret, to, out, err = execute_command(command, timeout=self.args.runner_timeout, merge_output=False)
            t_stop = time.time()
            exectime = t_stop - t_start
            self.debug_stack.append('executed in {} s'.format(exectime))
            reasons = self._find_reasons(ret, to, out, err, exectime)
            clog_reasons(sys.stdout, reasons)
            with open(self.files.blog, 'w') as ostr:
                ostr.write('[source] {}\n'.format(self.files.input))
                ostr.write(reasons)
                ostr.write('\n')
                ostr.write(out)
                ostr.write(err)
            if ret != 0 and not to:
                raise TaskException(reasons, out+err)
            self.status = TaskStatus.Complete
        except TaskException as e:
            self.status = TaskStatus.Failure
            self.debug_stack.append(e.log)
            self.debug_stack.append(e)
        except Exception as e:
            self.status = TaskStatus.HardFailure
            self.debug_stack.append(e)

    def _reasons_set(self, ret, to, out, err, etime):
        reasons = set()
        if ret != 0:
            reasons.add('nzr')
        if to:
            reasons.add('timeout')
        for logstr in out, err:
            with io.StringIO(logstr) as stream:
                for line in stream:
                    for risk, riskline in self.risks.items():
                        if risk in line:
                            reasons.add(riskline)
        if not reasons or reasons == { 'model' }:
            reasons.add('ok')
        return reasons

    def _find_reasons(self, ret, to, out, err, etime):
        reasons = self._reasons_set(ret, to, out, err, etime)
        ldata = list(reasons)
        ldata.sort()
        return '[{}binsec:run] {} in {} seconds'.format(self.runner_prefix, '+'.join(ldata), etime)
# ----------------------------------------
class AbduceTask(BinsecTask):

    risks = {
        'top-level' : 'top-level',
        'could not recover as many vulnerability models' : 'unreachable',
        'command timeouted' : 'binsec-timeout',
        'command failed' : 'binsec-failure',
        'satisfying solution' : 'solution(s)',
        'nas condition' : 'solution(c)',
        'necessary constraint' : 'solution(n)',
    }

    def _generate_command(self):
        return [ self.files.runner ] + self.args.forward_to_runner

    def _reasons_set(self, ret, to, out, err, etime):
        reasons = super()._reasons_set(ret, to, out, err, etime)
        if 'solution(s)' in reasons or 'solution(c)' in reasons:
            reasons.add('ok')
        return reasons

    def __init__(self, ifile, args):
        super().__init__(ifile, args, runner_prefix='abduce-')
# ----------------------------------------
