'''Base classes for building binary file faulters'''
# --------------------
# --------------------
class GenericFaulter:
    '''Generic class for faulting a binary file.

    :param opts: evaluator options
    :param log: logging utility class
    :type opts: :class:`fistic.FisticOptions`
    '''

    def __init__(self, opts, logger):
        self.opts = opts
        self.log = logger

    def __call__(self, mutant, mapping):
        '''Fault a binary file, updates file inplace.

        Apply the fault to the mutant, at each targeted location, inplace.

        :param mutant: the binary file and locations to fault
        :param mapping: an instruction map of the binary mutant
        :type mutant: :class:`fistic.placers.BinaryMutant`
        :type mapping: :class:`fistic.mapper.MapperCore`
        '''
        raise NotImplementedError(self)

    def inject_byte(self, target, addr, payload, relative=True):
        '''Modify binary file by replacing bytes.

        Replace the bytes of the target binary file, at address :code:`addr`,
        with the given payload.

        :param target: target binary filename
        :param addr: start address of byte replacement
        :param payload: bytes to replace the file content with
        :param relative: whether the address is relative to the .text section or not

        :type target: str
        :type addr: int
        :type payload: bytearray
        :type relative: bool
        '''
        offset = self.opts.textaddr if relative else 0
        with open(target, 'r+b') as fp:
            fp.seek(offset + addr)
            fp.write(payload)

    def flip_byte(self, target, addr, mask, relative=True):
        '''Modify binary file by flipping bits in bytes.

        Flips the bits in the target binary file, at address :code:`addr`,
        according to the given mask.

        :param target: target binary filename
        :param addr: start address of byte replacement
        :param mask: mask of the bits to flip
        :param relative: whether the address is relative to the .text section or not

        :type target: str
        :type addr: int
        :type mask: bytearray
        :type relative: bool
        '''
        offset = self.opts.textaddr if relative else 0
        with open(target, 'r+b') as fp:
            fp.seek(offset + addr)
            data = bytearray(fp.read(len(mask)))
            payload = bytearray([_d ^ _m for _d, _m in zip(data, mask)])
            fp.seek(offset + addr)
            fp.write(payload)
# --------------------
class NoFault(GenericFaulter):
    '''Utility faulter that does not modify the target binary.'''

    def __call__(self, mutant, mapping):
        pass
# --------------------
