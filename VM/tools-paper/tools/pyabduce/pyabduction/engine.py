# -------------------$
import itertools
# --------------------
from .storage import StorageTable
from .model import ModelTable
from pulseutils.strings import unparen, stringify
# --------------------
# --------------------
class AbstractCandidateEngine:

    def __init__(self, args, checkers, stats, logger, storage_structure=StorageTable, ci_structure=ModelTable):
        self.args = args
        self.checkers = checkers
        self.storage = storage_structure(args, checkers, logger, mode='exact')
        self.storage_unsol = storage_structure(args, checkers, logger)
        self.necessary = storage_structure(args, checkers, logger, mode='exact')
        self.examples = ci_structure(args, checkers, logger)
        self.counter_examples = ci_structure(args, checkers, logger)
        self.stats = stats
        self.log = logger

    def next_candidate(self):
        raise NotImplementedError(self)

    def significant_cex_element(self, elem):
        raise NotImplementedError(self)

    def get_solutions(self):
        return self.storage.solutions

    def get_stringified_solutions(self):
        return [stringify(sol) for sol in self.storage.solutions]

    def store_solution(self, candidate, core):
        self.stats.get_timer('solution').new()
        self.stats.solutions += 1
        self.storage.store(core if core is not None else candidate)

    def store_unsolution(self, candidate, core):
        self.stats.get_timer('unsolution').new()
        self.stats.unsolutions += 1
        self.storage_unsol.store(core if core is not None else candidate)

    def add_counter_example(self, cex):
        self.stats.get_timer('counterex').new()
        self.stats.counterex += 1
        self.counter_examples.add(cex)

    def add_example(self, ex):
        self.stats.get_timer('example').new()
        self.stats.examples += 1
        self.examples.add(ex)

    def get_example(self):
        return self.examples.get_any()

    def add_necessary_lit(self, lit):
        self.stats.get_timer('necessaryc').new()
        self.stats.necessaryc += 1
        self.necessary.store(lit)

    def extract_necessary_component(self):
        component = set()
        for lit in self.necessary:
            component = component | lit
        return component
# --------------------
class SimpleCandidateEngine(AbstractCandidateEngine):

    def __init__(self, args, checkers, coregen, stats, logger, storage_structure=StorageTable, ci_structure=ModelTable):
        super().__init__(args, checkers, stats, logger, storage_structure, ci_structure)
        self.coregen = coregen
        self.coregen.set_ex_set(self.examples)
        self.coregen.set_cex_set(self.counter_examples)

    def significant_cex_element(self, elem):
        return self.coregen.is_significant(elem)

    def check_consistency(self, candidate):
        return self.checkers.check_consistency(candidate)

    def check_satisfied(self, candidate, cex):
        return self.checkers.check_satisfied(candidate, cex)

    def check_consequence(self, sol, candidate):
        return self.checkers.check_consequence(sol, candidate)

    def restart_local_generation(self):
        self.coregen.restart_local_generation()
        self.coregen.set_ncore_set(self.extract_necessary_component())

    def recover_necessary_constants(self):
        # TODO: (1) From recovering models from binsec log, we might miss variables equaled to default value!!!
        # TODO: (1) Check if it is the case and if it is fix it
        # TODO: (2) Use multiple models if available to reduce the number of constants to check
        self.log.debug('recovering necessary constants')
        if len(self.examples.models) == 0:
            self.log.warning('no initial examples; skip necessary constant recovery')
            return
        emodel = self.get_example()
        emodel = { k : v for k, v in emodel.items() if not self.checkers.fully_assumed(k) }
        status, smodel, _ = self.checkers.check_vulnerability([], [emodel], complete=True)
        if status:
            self.log.info('no necessary constant detected')
            self.add_example(smodel)
        else:
            self.log.debug('necessary constants to recover')
            for key, val in emodel.items():
                if key != 'default' and not self.checkers.fully_assumed(key):
                    self.log.debug('checking necessary constant for {}'.format(key))
                    self.stats.get_oracle('constant-test').calls += 1
                    rstatus, _, _ = self.checkers.check_vulnerability([], [{key: val}], complete=True)
                    if not rstatus:
                        literal = self.checkers.as_literal({key: val})
                        self.log.result('necessary constraint: {}'.format(stringify(set([literal]))))
                        self.add_necessary_lit(set([literal]))

    def next_candidate(self):
        self.restart_local_generation()
        yield self.extract_necessary_component(), set()
        for candidate in self.coregen.generate():
            self.log.debug('pre-checking candidate: {}'.format(candidate))
            self.stats.generation.considered += 1
            valid = True
            ncomponent = self.extract_necessary_component()
            rcandidate = (ncomponent | candidate)
            # Consistency pruning
            cstatus, cmodel, ccore = self.check_consistency(candidate)
            if not cstatus:
                self.log.debug('candidate is inconsistent')
                self.stats.generation.pruned['consistency'] += 1
                continue
            # Counter-example pruning
            if self.args.prune_counterex:
                for cex in self.counter_examples:
                    # Skip pruning when the model carries no concrete assignments.
                    # An empty model makes every candidate appear "satisfied" and
                    # incorrectly prunes the entire search space.
                    if isinstance(cex, dict):
                        cex_nonmeta = {k: v for k, v in cex.items() if k != '*controlled'}
                        if (not cex_nonmeta) and (cex.get('*controlled') in (None, set())):
                            continue
                    status, _, _ = self.check_satisfied(rcandidate, cex)
                    if status:
                        self.log.debug('satisfied by {}'.format(cex))
                        valid = False
                        break
                if not valid:
                    self.stats.generation.pruned['counterex'] += 1
                    continue
            # Solutions, unsolutions and necessity pruning
            if self.args.prune_necessary:
                for strid, storage_struct, direct in (('solution', self.storage, True), ('unsolution', self.storage_unsol, True), ('necessary', self.necessary, False)):
                    for sol in storage_struct:
                        status, _, _ = self.check_consequence(rcandidate, sol) if direct else self.check_consequence(sol, rcandidate)
                        if status:
                            self.log.debug('has for consequence {}'.format(sol))
                            # TODO : distinguish stats and log for each storage structure
                            self.stats.generation.pruned[strid] += 1
                            valid = False
                            break
            if valid:
                yield rcandidate, candidate
# --------------------
class SimpleCandidateGenerator:

    def __init__(self, args, source, stats, logger):
        self.args = args
        self.source = source
        self.lits = []
        self.stats = stats
        self.log = logger

    def _load(self):
        with open(self.source) as stream:
            for line in stream:
                ldata = line.strip()
                if ldata != '':
                    self.lits.append(ldata)
        self.selems = { e.strip() for l in self.lits for e in l.split() }

    def set_cex_set(self, cexset):
        pass

    def set_ex_set(self, exset):
        pass

    def is_significant(self, elem):
        return '@[{},1]'.format(elem) in self.selems or elem in self.selems

    def generate(self):
        self._load()
        for depth in range(self.args.max_depth + 1):
            for candidate in itertools.combinations(self.lits, depth):
                yield set(candidate)
# --------------------
