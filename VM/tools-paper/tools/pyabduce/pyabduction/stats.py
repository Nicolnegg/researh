# -------------------$
import sys
import time
from statistics import mean, median
# --------------------
def cwrap(cmd, lst):
    return cmd(lst) if lst else -1
# --------------------
class StatTimer:

    def __init__(self):
        self.total = 0
        self.lstart = 0
        self.lstop = 0
        self.first = 0
        self.last = 0

    def start(self):
        self.lstart = time.time()

    def new(self):
        lnow = time.time()
        ldist = lnow - self.lstart
        self.last = ldist
        if self.first == 0:
            self.first = ldist

    def now(self):
        lnow = time.time()
        return self.total + lnow - self.lstart

    def stop(self):
        self.lstop = time.time()
        self.total += self.lstop - self.lstart
# --------------------
class OracleStats:

    def __init__(self):
        self.calls = 0
        self.timeouts = 0
        self.crashes = 0
        self.times = []
# --------------------
class GWrapper(dict):

    def __getitem__(self, k):
        if not k in self:
            self[k] = 0
        return super().__getitem__(k)
# --------------------
class GenerationStats:

    def __init__(self):
        self.evaluated = 0
        self.considered = 0
        self.restart = 0
        self.vars = 0
        self.literals = 0
        self.pruned = GWrapper()
# --------------------
class Stats:

    def __init__(self):
        self.solutions    = 0
        # Number of clauses kept in the final NAS condition (OR components).
        self.solution_clauses = 0
        # Number of final selected constraints (usually 1 when NAS exists).
        self.final_constraints = 0
        self.unsolutions  = 0
        self.examples     = 0
        self.counterex    = 0
        self.necessaryc   = 0

        self.oracle_stats = dict()
        self.generation   = GenerationStats()

        self.timers       = {}

    def get_oracle(self, key):
        if not key in self.oracle_stats:
            self.oracle_stats[key] = OracleStats()
        return self.oracle_stats[key]

    def get_timer(self, key):
        if not key in self.timers:
            self.timers[key] = StatTimer()
        return self.timers[key]

    def start_timers(self, keys):
        for key in keys:
            self.get_timer(key).start()

    def log(self, logger):
        logger.result('execution statistics:')

        logger.result('  core counters:')
        scount = self.solution_clauses if self.solution_clauses > 0 else self.solutions
        logger.result('    number of solution clauses:   {}'.format(scount))
        logger.result('    number of final constraints:  {}'.format(self.final_constraints))
        logger.result('    number of unsolutions:        {}'.format(self.unsolutions))
        logger.result('    number of examples:           {}'.format(self.examples))
        logger.result('    number of counter-examples:   {}'.format(self.counterex))
        logger.result('    number of necessary literals: {}'.format(self.necessaryc))

        logger.result('')
        logger.result('  oracles:')
        for oracle, ostats in self.oracle_stats.items():
            logger.result('    {}:'.format(oracle))
            logger.result('      * {} calls:    {}'.format(oracle, ostats.calls))
            logger.result('      * {} timeouts: {}'.format(oracle, ostats.timeouts))
            logger.result('      * {} crashes:  {}'.format(oracle, ostats.crashes))
            logger.result('      * {} times:    {}'.format(oracle, ostats.times))

        logger.result('')
        logger.result('  candidates generation:')
        logger.result('    number of restarts:     {}'.format(self.generation.restart))
        logger.result('    number of variables:    {}'.format(self.generation.vars))
        logger.result('    number of literals:     {}'.format(self.generation.literals))
        logger.result('    evaluated candidates:   {}'.format(self.generation.evaluated))
        logger.result('    considered candidates:  {}'.format(self.generation.considered))
        logger.result('    pruned candidates:      {}'.format(sum(self.generation.pruned.values())))
        for pcat, pval in self.generation.pruned.items():
            logger.result('      * {}-pruned candidates: {}'.format(pcat, pval))

        logger.result('')
        logger.result('  timers:')
        for timer, tstat in self.timers.items():
            logger.result('    {}:'.format(timer))
            logger.result('      * first {}: {}'.format(timer, tstat.first))
            logger.result('      * last  {}: {}'.format(timer, tstat.last))
# --------------------
# --------------------
