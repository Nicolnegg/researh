'''Module for placers placing from a given set of target addresses'''
# --------------------
import math
import itertools
# --------------------
from .core import GenericPlacer
# --------------------
class AddressesPlacer(GenericPlacer):
    '''Placer generating mutation targets from a set of addresses.

    Mutates at each given address, taken from :class:`fistic.FisticOptions`:code:`.addresses`.
    If more than one concomitent fault is expected, generates combinations of this set of
    addresses.
    '''

    @property
    def estimate(self):
        return math.comb(len(self.opts.addresses), self.opts.fault_count)

    def generate_addresses(self):
        '''Recover the addresses to fault.

        :rtype: list(int)
        '''
        return self.opts.addresses

    def generate_targets(self):
        addrs = self.generate_addresses()
        for target in itertools.combinations(addrs, self.opts.fault_count):
            yield target
# --------------------
# --------------------
# --------------------
