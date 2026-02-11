'''Module for payload injection faulters'''
# --------------------
import random
# --------------------
from .core import GenericFaulter
# --------------------
class PayloadInjection(GenericFaulter):
    '''Faulter that performs payload injection to the target binary.

    Faults each target instruction by replacing the existing bytes with
    the given payload indexed by the same size as the instruction.

    :param payloads: bytesized-indexed payloads for injection
    :type payloads: dict(int, bytearray)
    '''

    def __init__(self, opts, logger, payloads=None):
        super().__init__(opts, logger)
        self.payloads = payloads if payloads is not None else self.opts.payloads

    def __call__(self, mutant, mapping):
        for addr in mutant.targets:
            offset = 0
            for _ in range(self.opts.skip_count):
                isize = mapping.get_size(addr+offset)
                payload = self.payloads[isize]
                self.inject_byte(mutant.binary, addr+offset, payload)
                offset += isize
# --------------------
class RandomPayloadGenerator:
    '''Utility class for generating random payloads.

    :param opts: options
    :param log: logging utility class
    :type opts: :class:`fistic.FisticOptions`
    '''

    def __init__(self, opts, logger):
        self.opts = opts
        self.logger = logger
        random.seed(opts.random_payloads_seed)

    def __getitem__(self, size):
        '''Generates a random payload.

        :param size: number of bytes of the payload to generate
        :type size: int
        :return: a random payload of size :code:`size`
        :rtype: bytearray
        '''
        return bytearray([ random.randint(0, 0xff) for _ in range(size) ])
# --------------------
def RandomPayloadInjection(opts, logger):
    '''Utility function for obtaining a :code:`PayloadInjection` faulter with random payloads.

    Each time a new payload is required by the fault placer, it is randomly generated.

    :return: a :code:`PayloadInjection` faulter that randomly generated payloads
    :rtype: :code:`PayloadInjection` faulter
    '''
    return PayloadInjection(opts, logger, payloads=RandomPayloadGenerator(opts, logger))
# --------------------
