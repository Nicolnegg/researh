'''Base classes for building mutant placers, that decide where to mutate a binary file'''
# --------------------
import os.path
import shutil
# --------------------
from pulseutils.files import create_directory
from fistic.mapper import Mapper, MapperFromMap
# --------------------
class BinaryMutant:
    '''Abstract representation of a binary mutant.

    :param binary: the binary file of the mutant
    :param targets: faulted instruction adresses
    :type binary: str
    :type targets: list(int)
    '''

    def __init__(self, binary, targets):
        self.binary = binary
        self.targets = targets

    @property
    def targets_str(self):
        '''Obtain a string representation of the mutant's targets.

        :rtype: str
        '''
        return ', '.join((f'0x{loc:x}' for loc in self.targets))
# --------------------
class GenericPlacer:
    '''Generic class for placing faults in a mutant.

    Used to decide where to fault a source binary, build mutants accordingly
    and fault them.

    :param opts: evaluator options
    :param log: logging utility class
    :param cid: next mutant identifier
    :param mapping: source binary instruction mapping
    :type opts: :class:`fistic.FisticOptions`
    :type cid: int
    :type mapping: :class:`fistic.mapper.MapperCore`
    '''

    def __init__(self, opts, logger):
        self.opts = opts
        self.log = logger
        self.cid = 0
        self.mapping = None
        if self.opts.map is None:
            self.mapping = Mapper(self.opts.binary, self.log, self.opts.mapper)
        else:
            self.mapping = MapperFromMap(self.opts.binary, self.log, self.opts.map)

    @property
    def estimate(self):
        '''Estimate the number of mutants to generate for this fault placer.

        :return: an estimation of the number of mutants that will be generated
        :rtype: int
        '''
        raise NotImplementedError(self)

    def _new_binary(self):
        '''Create a new copy of the source binary.

        Creates a new copy of :code:`opts.binary` in :code:`opts.faulted_binaries_dir`,
                named :code:`opts.faulted_binaries_template.format(id)` and increases the internal binary id.

        :return: path to the new binary copy
        :rtype: str
        '''
        create_directory(self.opts.faulted_binaries_dir)
        binfile = self.opts.faulted_binaries_template.format(self.cid)
        binfile = os.path.join(self.opts.faulted_binaries_dir, binfile)
        shutil.copyfile(self.opts.binary, binfile)
        self.cid += 1
        return binfile

    def generate_mutants(self, faulter):
        '''Generate the faulted mutants.

        Generates in :code:`opts.faulted_binaries_dir` all the mutants corresponding the application of the underlying fault model.

        :return: generator returning the fistic representation of the created binary mutant, fault applied
        :rtype: generator(:class:`fistic.placers.BinaryMutant`)
        '''
        for target in self.generate_targets():
            binfile = self._new_binary()
            mutant = BinaryMutant(binfile, target)
            faulter(mutant, self.mapping)
            yield mutant

    def generate_targets(self):
        '''Generate the list of addresses to fault for each mutant to fault.

        :return: generator returning which addresses to fault for each mutant binary
        :rtype: generator(tuple(int))
        '''
        raise NotImplementedError(self)
# --------------------
class NowherePlacer(GenericPlacer):
    '''Utility class for placing no mutation whatsoever.
    '''

    @property
    def estimate(self):
        return 0

    def generate_targets(self):
        return ()
# --------------------
