'''Utility placers for placing faults on all the addresses of a function'''
# --------------------
import math
import itertools
# --------------------
from .address import AddressesPlacer
# --------------------
class FunctionsPlacer(AddressesPlacer):
    '''Place faults on all the addresses of the target functions.

    Behaves as :class:`fistic.placers.AddressesPlacer` with the addresses of the target functions,
    taken from :class:`fistic.FisticOptions`:code:`.functions`.

    Build combinations on the complete set of addresses.
    '''

    @property
    def estimate(self):
        return math.comb(sum((len(self.mapping[f]) for f in self.opts.functions)), self.opts.fault_count)

    def generate_function_addresses(self, fun):
        '''Generates the set of addresses of a given function.

        Excludes inline data addresses if :class:`fistic.FisticOptions`:code:`.dont_fault_data` is set.

        :param fun: target function
        :type fun: str
        :return: the set of addresses of :code:`fun`
        :rtype: collection(int)
        '''
        if self.opts.dont_fault_data:
            return ( a for a, bdl in self.mapping[fun].items() if bdl.is_inst() )
        return self.mapping[fun].keys()

    def generate_addresses(self):
        addrs = []
        for fun in self.opts.functions:
            addrs.extend(self.generate_function_addresses(fun))
        return addrs
# --------------------
class OnFunctionPlacer(FunctionsPlacer):
    '''Place faults on single function addresses.

    Behaves as :class:`fistic.placers.FunctionPlacer` for single faults.
    For multifault, faults are always injected in the same function.
    '''

    def generate_targets(self):
        for fun in self.opts.functions:
            addrs = self.generate_function_addresses(fun)
            for target in itertools.combinations(addrs, self.opts.fault_count):
                yield target
# --------------------
# --------------------
