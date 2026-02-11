'''Base classes for building mutant evaluators'''
# --------------------
import enum
# --------------------
# --------------------
class EvaluationStatus(enum.Enum):
    '''Result of a mutant evaluation'''
    Valid   = 'valid'
    Invalid = 'invalid'
    Timeout = 'timeout'
    Failure = 'failure'
    Nodata  = 'no data'

    def __str__(self):
        return self.value
# --------------------
class GenericEvaluator:
    '''Generic class for evaluating generated binary mutants.

    If the source binary contains a validation oracle, fistic can use an evaluator to detect
    if the oracle is triggered by the mutant.

    :param opts: evaluator options
    :param log: logging utility class
    :type opts: :class:`fistic.FisticOptions`
    '''

    def __init__(self, opts, logger):
        self.opts = opts
        self.log = logger

    def __call__(self, mutant, golden=False):
        '''Evaluate a single mutant.

        :param mutant: mutant to evaluate
        :param golden: whether the evaluated mutant should be considered as a golden run
        :type mutant: :class:`fistic.placers.BinaryMutant`
        :type golden: bool

        :return: the mutant and its evaluation result
        :rtype: :class:`fistic.placers.BinaryMutant`, :class:`fistic.evaluators.EvaluationStatus`
        '''
        raise NotImplementedError(self)
# --------------------
class NoneEvaluator(GenericEvaluator):
    '''Basic evaluation class for not performing any evaluation.

    Always evaluates to :class:`fistic.evaluators.EvaluationStatus`:code:`.Nodata`
    '''

    def __call__(self, mutant, golden=False):
        return mutant, EvaluationStatus.Nodata
# --------------------
