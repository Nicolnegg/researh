'''Fistic core utilities, entrypoint for complete evaluation'''
# --------------------
import sys
import enum
import concurrent.futures
# --------------------
import yaml
try:
    from yaml import CLoader as ymlLoader, CDumper as ymlDumper
except ImportError:
    from yaml import Loader as ymlLoader, Dumper as ymlDumper
# --------------------
from pulseutils.logging import Logger
# --------------------
from fistic.placers.core import BinaryMutant
from fistic.placers import *
from fistic.faulters import *
from fistic.evaluators import *
# --------------------
class ArticulationMode(enum.Enum):
    '''Articulation mode for the fistic mutant handling.

    :param Linear: evaluate one mutant after the other automatically
    :param Parallel: evaluate mutants in parallel (max thread availability)
    :param Communicate: evaluate mutants on reading `next` from `stdin`
    '''

    Linear = 'linear'
    Parallel = 'parallel'
    Communicate = 'communicate'

    def __str__(self):
        return self.value
# --------------------
def get_articulation_mode(parallel, communicate):
    '''Select the fistic articulation mode from option flags.

    :param parallel: handle mutants in parallel flag
    :param communicate: handle mutants on reading query from stding flag
    :type parallel: bool
    :type communicate: bool

    :return: the articulation mode described by the flags, parallel has priority
    :rtype: :class:`fistic.ArticulationMode`
    '''
    if parallel:
        return ArticulationMode.Parallel
    if communicate:
        return ArticulationMode.Communicate
    return ArticulationMode.Linear
# --------------------
Placers = {
    'none': NowherePlacer,
    'address': AddressesPlacer,
    'function': FunctionsPlacer,
    'on-function': OnFunctionPlacer,
}
Faulters = {
    'none': NoFault,
    'skip': InstructionSkipper,
    'replace': InstructionReplacer,
    'payload': PayloadInjection,
    'random-payload': RandomPayloadInjection,
    'bitflip': BitflipFaulter,
}
Evaluators = {
    'none': NoneEvaluator,
    'qemu': QemuEvaluator,
}
# --------------------
class FisticOptions:
    '''Options for Fistic executions.

    Built in the following prioriy order: kwargs -> args -> default.
    Unless specified otherwise, the input attribute name of key name is
    identical to the option attribute name.

    :param binary: source binary to mutate, default `input.bin`
    :param textaddr: address of the `.text` segment of the source binary, reads from `args.text_segment_address`, default `0x8000`
    :param golden_mutant: evaluation key for the results of the source binary, must not conflict with `faulted_binaries_template`, default to `**golden**`
    :param log: logging option flags, reads from `log_debug`, `log_color` and `log_progress` (except: `args.debug`), default to False

    :type binary: str
    :type textaddr: int
    :type golden_mutant: str
    :type log: dict(str, bool)

    .. todo::

        Complete options descriptions
    '''

    def __init__(self, args=None, **kwargs):
        self.binary = (kwargs['binary'] if 'binary' in kwargs else
                       args.binary if args is not None else
                       'input.bin')
        self.textaddr = (kwargs['textaddr'] if 'textaddr' in kwargs else
                         args.text_segment_address if args is not None else
                         0x8000)
        self.output_file = (kwargs['output_file'] if 'output_file' in kwargs else
                            args.output_file if args is not None else
                            'fistic-results.yml')

        self.golden_mutant = (kwargs['golden_mutant'] if 'golden_mutant' in kwargs else
                              args.golden_mutant if args is not None else
                              '**golden**')

        self.log = {
            'debug': (kwargs['log_debug'] if 'log_debug' in kwargs else
                      args.debug if args is not None else
                      False),
            'color': (kwargs['log_color'] if 'log_color' in kwargs else
                      args.log_color if args is not None else
                      False),
            'progress': (kwargs['log_progress'] if 'log_progress' in kwargs else
                         args.log_progress if args is not None else
                         False),
        }

        self.placer = (kwargs['placer'] if 'placer' in kwargs else
                       Placers[args.placer] if args is not None else
                       NowherePlacer)
        self.faulter = (kwargs['faulter'] if 'faulter' in kwargs else
                        Faulters[args.fault_model] if args is not None else
                        NoFault)
        self.evaluator = (kwargs['evaluator'] if 'evaluator' in kwargs else
                          Evaluators[args.evaluator] if args is not None else
                          NoneEvaluator)

        self.mode = (kwargs['articulation_mode'] if 'articulation_mode' in kwargs else
                     get_articulation_mode(args.parallel, args.communicate) if args is not None else
                     ArticulationMode.Linear)

        self.faulted_binaries_dir = (kwargs['faulted_binaries_dir'] if 'faulted_binaries_dir' in kwargs else
                                     args.faulted_binaries_dir if args is not None else
                                     'fistic_mutants')
        self.faulted_binaries_template = (kwargs['faulted_binaries_template'] if 'faulted_binaries_template' in kwargs else
                                          args.faulted_binaries_template if args is not None else
                                          'f{}.bin')

        self.map = (kwargs['map'] if 'map' in kwargs else
                    args.map if args is not None else
                    None)
        self.mapper = (kwargs['mapper'] if 'mapper' in kwargs else
                       args.mapper if args is not None else
                       'pulseutils')

        self.fault_count = (kwargs['fault_count'] if 'fault_count' in kwargs else
                            args.fault_count if args is not None else
                            1)
        self.skip_count = (kwargs['skip_count'] if 'skip_count' in kwargs else
                           args.skip_count if args is not None else
                           1)
        self.dont_fault_data = (kwargs['dont_fault_data'] if 'dont_fault_data' in kwargs else
                                args.dont_fault_data if args is not None else
                                False)

        self.functions = (kwargs['functions'] if 'functions' in kwargs else
                          args.functions if args is not None else
                          ())
        self.addresses = (kwargs['addresses'] if 'addresses' in kwargs else
                          args.addresses if args is not None else
                          ())

        self.evaluation_timeout = (kwargs['evaluation_timeout'] if 'evaluation_timeout' in kwargs else
                                   args.evaluation_timeout if args is not None else
                                   None)
        self.qemu_oracle = (kwargs['qemu_oracle'] if 'qemu_oracle' in kwargs else
                            args.qemu_oracle if args is not None else
                            'stderr')

        self.random_payloads_seed = (kwargs['random_payloads_seed'] if 'random_payloads_seed' in kwargs else
                                     args.random_payloads_seed if args is not None else
                                     None)
        self.payloads = (kwargs['payloads'] if 'payloads' in kwargs else
                        # args.payloads if args is not None else
                         None)
        self.masks = (kwargs['masks'] if 'masks' in kwargs else
                    # args.masks if args is not None else
                      None)

    def create_placer(self, logger):
        '''Create and initialize a Placer from current options.

        :param logger: logging utility class

        :return: an initialized Placer
        :rtype: :class:`fistic.placers.core.GenericPlacer`
        '''
        return self.placer(self, logger)

    def create_faulter(self, logger):
        '''Create and initialize a Faulter from current options.

        :param logger: logging utility class

        :return: an initialized Faulter
        :rtype: :class:`fistic.faulters.core.GenericFaulter`
        '''
        return self.faulter(self, logger)

    def create_evaluator(self, logger):
        '''Create and initialize an Evaluator from current options.

        :param logger: logging utility class

        :return: an initialized Evaluator
        :rtype: :class:`fistic.evaluators.core.GenericEvaluator`
        '''
        return self.evaluator(self, logger)
# --------------------
class Articulator:
    '''Main class for running a complete fistic evaluation.

    :param opts: options for the evaluation
    :param log: logging utility class
    :param results: evaluation results, set after call
    :type opts: :class:`fistic.FisticOptions`
    :type results: dict(:class:`fistic.placers.BinaryMutant`, :class:`fistic.evaluators.EvaluationStatus`)
    '''

    def __init__(self, opts):
        self.opts = opts
        self.log = Logger(level=4 if opts.log['debug'] else 3, color=opts.log['color'], log_progress=opts.log['progress'])
        self.results = {}

    def export_results(self, target):
        '''Export the results to the target file descriptor.

        :param target: target to write the results to
        :type target: fp('w')
        '''
        yaml.dump(self.results, target, Dumper=ymlDumper)

    def __call__(self):
        '''Run the complete fistic evaluation.

        This includes generating the binary mutants, faulting them, evaluating them and storing the results.
        '''
        self.log.debug('initializing fistic articulator')
        placer = self.opts.create_placer(self.log)
        faulter = self.opts.create_faulter(self.log)
        evaluator = self.opts.create_evaluator(self.log)

        self.log.info(f'performing golden run (target: {self.opts.binary})')
        golden, grr = evaluator(BinaryMutant(self.opts.binary, []), golden=True)
        self.results[golden] = grr
        self.log.info(f'golden run evaluation result: {grr}')

        if self.opts.mode == ArticulationMode.Linear:
            self.__articulate_linear(placer, faulter, evaluator)
        elif self.opts.mode == ArticulationMode.Parallel:
            self.__articulate_parallel(placer, faulter, evaluator)
        elif self.opts.mode == ArticulationMode.Communicate:
            self.__articulate_communicate(placer, faulter, evaluator)

        with open(self.opts.output_file, 'w') as stream:
            self.export_results(stream)

    def __articulate_linear(self, placer, faulter, evaluator):
        for mutant in placer.generate_mutants(faulter):
            self.log.debug(f'evaluating {mutant.binary} (mutated: {mutant.targets_str})')
            _, result = evaluator(mutant)
            self.log.result(f'faulted binary {mutant.binary} (mutated: {mutant.targets_str}): {result}')
            self.results[mutant] = result

    def __articulate_parallel(self, placer, faulter, evaluator):
        with concurrent.futures.ThreadPoolExecutor() as executor:
            tp = ( executor.submit(evaluator, mutant) for mutant in placer.generate_mutants(faulter) )
            for tres in concurrent.futures.as_completed(tp):
                mutant, result = tres.result()
                self.log.result(f'faulted binary {mutant.binary} (mutated: {mutant.targets_str}): {result}')
                self.results[mutant] = result

    def __articulate_communicate(self, placer, faulter, evaluator):
        self.log.result(f'expected number of binaries: {placer.estimate}')
        self.__get_communicated('next')
        for mutant in placer.generate_mutants(faulter):
            self.log.debug(f'evaluating {mutant.binary} (mutated: {mutant.targets_str})')
            _, result = evaluator(mutant)
            self.log.result(f'faulted binary {mutant.binary} (mutated: {mutant.targets_str}): {result}')
            self.results[mutant] = result
            self.__get_communicated('next')
        self.log.result('evaluation completed')

    def __get_communicated(self, command):
        try:
            while sys.stdin.readline().rstrip() != command:
                pass
        except EOFError:
            self.log.error('communication lost')
# --------------------
# --------------------
# --------------------
# --------------------
# --------------------
# --------------------
