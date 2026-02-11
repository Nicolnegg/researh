'''Module for bitflip faulters'''
# --------------------
from .core import GenericFaulter
# --------------------
class BitflipFaulter(GenericFaulter):
    '''Faulter that performs a bitflip injection to the target binary.

    Flips the bits of the target instruction according to the given mask,
    indexed by the same size as the instruction.

    :param masks: bytesized-indexed masks for injection
    :type masks: dict(int, bytearray)
    '''

    def __init__(self, opts, logger, masks=None):
        super().__init__(opts, logger)
        self.masks = masks if masks is not None else self.opts.masks

    def __call__(self, mutant, mapping):
        for addr in mutant.targets:
            offset = 0
            for _ in range(self.opts.skip_count):
                isize = mapping.get_size(addr+offset)
                mask = self.masks[isize]
                self.flip_byte(mutant.binary, addr+offset, mask)
                offset += isize
# --------------------
# --------------------
# --------------------
