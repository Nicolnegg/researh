# -------------------$
# --------------------
# --------------------
from pulseutils.strings import stringify
# --------------------
class AbductionSolver:

    def __init__(self, args, engine, checkers, stats, logger):
        self.args = args
        self.engine = engine
        self.checkers = checkers
        self.stats = stats
        self.log = logger

    def next_candidate(self):
        return self.engine.next_candidate()

    def check_goals(self, candidate):
        return self.checkers.check_goals(candidate)

    def check_necessity(self, formula):
        return self.checkers.check_necessity(formula)

    def check_vulnerability(self, candidate, reject):
        return self.checkers.check_vulnerability(candidate, reject)

    def store_solution(self, candidate, gcore):
        return self.engine.store_solution(candidate, gcore)

    def store_unsolution(self, candidate, gcore):
        return self.engine.store_unsolution(candidate, gcore)

    def get_vulnerability_model(self, vset):
        return self.checkers.check_vulnerability([], vset)[1]

    def get_initital_examples(self):
        vinit_count = max(self.args.vexamples_init_count, 1 if self.args.const_detect else 0)
        for cpt in range(vinit_count):
            vmodel = self.get_vulnerability_model(self.engine.examples)
            if vmodel is not None:
                self.log.info('initialization vulnerability example: {}'.format(vmodel))
                self.engine.add_example(vmodel)
            else:
                self.log.warning('could not recover as many vulnerability models as requested ({} only)'.format(cpt))
                #TODO : act in consequence

    def recover_necessary_constants(self):
        self.engine.recover_necessary_constants()

    def solve(self):
        self.stats.start_timers(('solution', 'unsolution', 'counterex', 'example', 'necessaryc'))
        self.get_initital_examples()
        if self.args.const_detect:
            self.recover_necessary_constants()
        for candidate, core_candidate in self.next_candidate():
            self.log.debug('trying candidate: {}'.format(candidate))
            self.log.debug('candidate is consistent')
            self.log.info('evaluating candidate: {}'.format(candidate))
            self.stats.generation.evaluated += 1
            gstatus, rstatus, gmodel, rmodel, gcore, rcore = self.check_goals(candidate)
            if gstatus and rstatus:
                self.log.result('satisfying solution: {}'.format(stringify(candidate)))
                self.store_solution(candidate, gcore)
                self.engine.add_example(rmodel)
                if self.check_necessity(self.engine.get_solutions()):
                    self.log.info('obtained a necessary result set')
                    self.log.result('nas condition: {}'.format(self.engine.get_stringified_solutions()))
                    break
                self.log.result('updated sufficient condition: {}'.format(self.engine.get_stringified_solutions()))
            elif gstatus:
                self.log.debug('locally inconsistent candidate')
                self.store_unsolution(candidate, gcore)
            elif gmodel is not None:
                self.log.info('counter-example: {}'.format(gmodel))
                self.engine.add_counter_example(gmodel)
                if len(core_candidate) == 1:
                    self.log.debug('check candidate necessity')
                    #TODO: Handle higher level necessary constraints
                    #TODO: WARNING: checkers.negate negates literal by literal, not literal combining operators!!!
                    nstatus, nmodel, ncore = self.check_vulnerability(self.checkers.negate(core_candidate), [])
                    if not nstatus:
                        self.log.result('necessary constraint: {}'.format(stringify(core_candidate)))
                        self.engine.add_necessary_lit(core_candidate)
                        self.engine.restart_local_generation()
                    elif self.args.force_on_model_resorting:
                        self.engine.add_example(nmodel)
                        # TODO: Restart is not required here, only resorting, but no primitive exist
                        self.engine.restart_local_generation()
            else:
                self.log.debug('unsatisfying example with no counter-example')
# --------------------
