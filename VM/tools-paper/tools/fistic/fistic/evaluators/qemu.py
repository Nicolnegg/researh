'''A qemu-based mutant evaluator'''
# --------------------
import sys
import time
import shlex
import subprocess
from subprocess import Popen, TimeoutExpired
# --------------------
from .core import EvaluationStatus, GenericEvaluator
# --------------------
class QemuRun:
    '''Utility class for calling qemu and recovering its execution results.'''

    def __init__(self, command, timeout, opts):
        '''
        :param command: qemu command to execute
        :param timeout: qemu run timeout
        :param opts: context fistic options
        :type command: str
        :type timeout: float or None
        :type opts: :class:`fistic.FisticOptions`
        '''
        self.command = command
        self.timeout = timeout
        self.opts = opts
        self.did_timeout = False
        self.did_fail = False
        self.ctime = -1
        self.log = None

    def run(self):
        '''Executes the qemu evaluation.'''
        proc = Popen(shlex.split(self.command), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time_start = time.time()
        try:
            cout, cerr = proc.communicate(timeout=self.timeout)
        except TimeoutExpired:
            proc.kill()
            cout, cerr = proc.communicate()
            self.did_timeout=True
        time_stop = time.time()
        self.ctime = time_stop - time_start
        self.did_fail = proc.returncode != 0
        if self.opts.qemu_oracle == 'stdout':
            self.log = cout.decode(sys.stdout.encoding, errors='ignore') if cout is not None else None
        elif self.opts.qemu_oracle == 'stderr':
            self.log = cerr.decode(sys.stderr.encoding, errors='ignore') if cerr is not None else None
        elif self.opts.qemu_oracle == 'rv':
            self.log = proc.returncode
        else:
            raise KeyError(self.opts.qemu_oracle)

    def status(self, golden):
        '''Recover the evaluation status of the given qemu run.

        Depends on the given oracle.

        :rtype: :class:`fistic.evaluators.EvaluationStatus`
        '''
        if '==VERDICT== FAIL' in self.log:
            return EvaluationStatus.Invalid
        if '==VERDICT== OK' in self.log:
            return EvaluationStatus.Valid
        if self.did_timeout:
            return EvaluationStatus.Timeout
        if self.did_fail:
            return EvaluationStatus.Failure
        return EvaluationStatus.Nodata
# --------------------
class QemuEvaluator(GenericEvaluator):
    '''A qEMU-based mutant evaluation.

    Evaluates the mutant by running qemu and checking for the given execution oracle.
    See :ref:`qemu-evaluation` for more detail on making this work.

    :param server: core qemu command
    :param golden: execution time of the golden run, if available
    :type server: str
    :type golden: float or None
    '''

    DefaultTimeout = 10

    def __init__(self, opts, logger):
        super().__init__(opts, logger)
        self.server = 'qemu-system-arm -machine lm3s6965evb -cpu cortex-m3 -nographic -monitor null -serial null -semihosting -kernel'
        self.golden = None

    def generate_command(self, binary):
        '''Generates the qemu command to execute for evaluating a binary.

        :param binary: target filename
        :type binary: str
        :return: the os command to evaluate :code:`binary` with qemu
        :rtype: str
        '''
        return f'{self.server} {binary}'

    def get_timeout(self):
        '''Compute the timeout for a given qemu run.

        This is recovered in the following priority:
         - :class:`fistic.FisticOptions`:code:`.evaluation_timeout`
         - ten times the execution time of the golden run, if available
         - the default timeout
        
        :rtype: float or None
        '''
        if self.opts.evaluation_timeout:
            return self.opts.evaluation_timeout
        if self.golden is not None:
            return 10.0 * self.golden.ctime
        return self.DefaultTimeout

    def __call__(self, mutant, golden=False):
        command = self.generate_command(mutant.binary)
        runner = QemuRun(command, self.get_timeout(), self.opts)
        runner.run()
        if golden:
            self.golden = runner
        return mutant, runner.status(self.golden)
# --------------------
# --------------------
