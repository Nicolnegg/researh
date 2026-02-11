# -------------------
import sys, os
import copy
import time
from enum import Enum
from subprocess import Popen, STDOUT, PIPE, TimeoutExpired
import traceback
import resource
try:
    import importlib.resources as resources
except ImportError:
    import importlib_resources as resources
import yaml
try:
    from yaml import CLoader as ymlLoader, CDumper as ymlDumper
except ImportError:
    from yaml import Loader as ymlLoader, Dumper as ymlDumper
# --------------------
SEATIC_TASK_ID = 0
def generate_task_id():
    global SEATIC_TASK_ID
    SEATIC_TASK_ID += 1
    return SEATIC_TASK_ID
# --------------------
class TaskProcessStatus(Enum):
    preprocess = "preprocess"
    execution = "execution"
    postprocess = "postprocess"
# --------------------
class Task:

    def __init__(self, logger):
        self.log = logger
        self.tid = generate_task_id()
        self.started = False
        self.finished = False

    def execute(self):
        self.started = True
        try:
            status = TaskProcessStatus.preprocess
            self._preprocess()
            status = TaskProcessStatus.execution
            self._execute()
            status = TaskProcessStatus.postprocess
            self._postprocess()
        except Exception as e:
            self.log.error('exception {} raised in task {} ({}) during {}'.format(e, self.tid, self, status))
            for line in traceback.format_exc().split('\n'):
                if line:
                    self.log.error(line)
        self.finished = True

    def _execute(self):
        raise NotImplementedError(self)

    def _preprocess(self):
        pass

    def _postprocess(self):
        pass

# --------------------
class CmdResult:

    def __init__(self, out, err, returncode, time, timeout):
        self.out = out
        self.err = err
        self.returncode = returncode
        self.time = time
        self.timeout = timeout

class SystemTask(Task):

    def __init__(self, cmd, logger, timeout=None, unified_log=True, log_errors=True, shell=False, softkill=False):
        super().__init__(logger)
        self.cmd = cmd
        self._extend_cmd()
        self.cmd_result = None
        self.timeout = timeout
        self.unified_log = unified_log
        self.log_errors = log_errors
        self.shell = shell
        self.softkill = softkill

    def _extend_cmd(self):
        if isinstance(self.cmd[0], list):
            self.cmd = self.cmd[0] + self.cmd[1:]

    def _log_output(self, logfile):
        logdir = os.path.dirname(logfile)
        if logdir and not os.path.isdir(logdir):
            os.makedirs(logdir)
        self.log.debug('writing to {}'.format(logfile))
        stream = open(logfile, 'w')
        stream.write(self.cmd_result.out)
        stream.close()

    def _clear_output(self):
        if self.cmd_result is not None:
            self.cmd_result.out = None
            self.cmd_result.err = None

    @property
    def output(self):
        return self.cmd_result.out if self.cmd_result is not None else None

    def _execute(self):
        self.log.debug('running: {}'.format(' '.join(self.cmd)))
        #prvp_time = resource.getrusage(resource.RUSAGE_CHILDREN).ru_utime
        env = copy.deepcopy(os.environ)
        env['TMPDIR'] = self.ctx['environ.TMPDIR']
        if not os.path.isdir(env['TMPDIR']):
            os.makedirs(env['TMPDIR'])
        prvp_time = time.time()
        proc = Popen(self.cmd, stdout=PIPE, stderr=(STDOUT if self.unified_log else PIPE), shell=self.shell, env=env)
        to_status = False
        try:
            cout, cerr = proc.communicate(timeout=self.timeout)
        except TimeoutExpired:
            if self.log_errors:
                self.log.warning('command did timeout: {}'.format(self.cmd))
            to_status = True
            if self.softkill:
                proc.terminate()
            else:
                proc.kill()
            cout, cerr = proc.communicate()
        if self.log_errors and proc.returncode != 0:
            self.log.error('command raised error: {} ({})'.format(self.cmd, proc.returncode))
        #proc_time = resource.getrusage(resource.RUSAGE_CHILDREN).ru_utime - prvp_time
        proc_time = time.time() - prvp_time
        proc_time = round(proc_time, 6)
        self.log.debug('process elapsed time: {}s'.format(proc_time))
        self.cmd_result = CmdResult(cout.decode(sys.stdout.encoding, errors='ignore'), cerr.decode(sys.stderr.encoding, errors='ignore') if cerr is not None else None,
                                    proc.returncode, proc_time, to_status)
# --------------------
class SeaticContext:
    
    def __init__(self, logger):
        self.log = logger
        with resources.open_text('seatic.data.core', 'init-context.yml') as stream:
            self.data = yaml.load(stream, Loader=ymlLoader)

    def update_from(self, ctxdata):
        def update_dict(target, source):
            for key in source:
                if key in target:
                    if isinstance(target[key], dict):
                        update_dict(target[key], source[key])
                    else:
                        self.log.info('updating context @{}: {} <- {}'.format(key, target[key], source[key]))
                        target[key] = source[key]
                else:
                    self.log.debug('supplementing context @{}: / <- {}'.format(key, source[key]))
                    target[key] = source[key]
        update_dict(self.data, ctxdata)

    def update_fargs(self, args):
        if args.binsec_from_robust:
            self.log.info('binsec is now binsec-robust')
            self['tool.binsec'] = self['tool.binsec-robust']
        self._override_fargs(args)
        self._prefixate_fargs(args)

    def _override_fargs(self, args):
        for override in args.override_context:
            key, val = tuple(override)
            self.log.info('overriding context from cli: @{}: {} <- {}'.format(key, self[key], val))
            self[key] = eval(val)

    def _prefixate_fargs(self, args):
        if args.context_prefix is not None:
            for key in self['type.prefixable']:
                if key in self:
                    self[key] = os.path.join(args.context_prefix, self[key])

    def mutant_logtarget(self, mutant, logdir, ext='log'):
        return os.path.join(self['log'][logdir], '{}.{}'.format(os.path.basename(mutant), ext))

    def mutant_assfile(self, mutant):
        return self.mutant_logtarget(mutant, 'assembly', 's')

    def is_vulnerable(self, mutant, mdata=None):
        if mdata is not None:
            return mdata['binsec']['vulnerable']
        try:
            return self.mutants[mutant]['binsec']['vulnerable']
        except KeyError as e:
            self.log.error('{}: mutant {} has no vulnerability data'.format(self.data['source'], mutant))
            # raise e

    @property
    def mutants(self):
        return self.data['mutants']

    def expand_models(self):
        for mutant in self.mutants:
            if 'binsec' in  self.mutants[mutant] and self.is_vulnerable(mutant):
                self._resolve_model_addrs(mutant)

    def _resolve_model_addrs(self, mutant):
        for vuln in self.mutants[mutant]['binsec']['models']:
            rmodel = {}
            for k, v in vuln['model'].items():
                rmodel[self.resolve_addr(mutant, k)] = v
            vuln['model'] = rmodel

    def resolve_addr(self, mutant, address, unpack=False, repack=False):
        memory = self.mutants[mutant]['memory']
        memoryddrs = sorted(memory.keys())
        addr = address
        size = None
        if unpack:
            addr, size = self._unpack_addr(addr)
        result = addr
        if addr.startswith('0x'):
            iaddr = int(addr, 16)
            if iaddr in memoryddrs:
                if size is not None:
                    result = '{}+0x0'.format(memory[iaddr])
                else:
                    result = memory[iaddr]
            else:
                iloc = 0
                while iloc < len(memoryddrs) and memoryddrs[iloc] < iaddr:
                    iloc += 1
                if iloc > 0:
                    raddr = memoryddrs[iloc - 1]
                    delta = iaddr - raddr
                    result = '{}+0x{:x}'.format(memory[raddr], delta)
        if repack:
            result = self._repack_addr(result)
        return result

    def _unpack_addr(self, addr):
        if addr.startswith('@['):
            splits = addr[2:-1].split(',')
            return splits[0].strip(), int(splits[1])
        return addr, None

    def _repack_addr(self, addr):
        return '@[{}]'.format(addr)

    def __contains__(self, k):
        data = self.data
        if k:
            kids = k.split('.')
            for kid in kids:
                if not kid in data:
                    return False
                data = data[kid]
        return True

    def __setitem__(self, k, v):
        data = self.data
        kids = k.split('.')
        for i in range(len(kids)):
            if i + 1 == len(kids):
                data[kids[i]] = v
            else:
                if not kids[i] in data:
                    data[kids[i]] = dict()
                data = data[kids[i]]

    def __getitem__(self, k):
        data = self.data
        if k:
            kids = k.split('.')
            for kid in kids:
                if not kid in data:
                    data[kid] = dict()
                data = data[kid]
        return data
# --------------------
