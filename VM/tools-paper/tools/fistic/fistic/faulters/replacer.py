'''Module for instruction replacement faulters'''
# --------------------
from .payload import PayloadInjection
# --------------------
InstructionPayloads = {
    'NOP': { 2: bytearray([0x00,0xbf]), 4: bytearray([0xaf,0xf3,0x00,0x80]) },
}
# --------------------
class InstructionReplacer(PayloadInjection):
    '''Faulter that replaces targeted instructions by its parameter.

    Performs a payload injection with the payload corresponding to the
    instruction to replace with, given its identifer in the :code:`InstructionPayloads` table.
    '''

    def __init__(self, opts, logger, replace_with=None):
        super().__init__(opts, logger, InstructionPayloads[replace_with if replace_with is not None else self.opts.replace_by])
# --------------------
def InstructionSkipper(opts, logger):
    '''Utility function for obtaining a :class:`fistic.placers.InstructionReplacer` replacing by :code:`NOP`.

    :rtype: :class:`fistic.placers.InstructionReplacer`
    '''
    return InstructionReplacer(opts, logger, 'NOP')
# --------------------
# --------------------
