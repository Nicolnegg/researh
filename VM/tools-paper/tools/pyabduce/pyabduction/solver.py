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
        self.result_summary = {
            'selected_policy': None,
            'alternatives': [],
            'nas_conditions_all': [],
            'ct_validation': None,
        }

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

    def _literal_complexity(self, lit):
        cfun = getattr(lit, 'complexity', None)
        if callable(cfun):
            try:
                return int(cfun())
            except Exception:
                return 0
        return 0

    def _stable_solution_literals(self, solution):
        return sorted((str(lit) for lit in solution))

    def _stable_solution_string(self, solution):
        lits = self._stable_solution_literals(solution)
        return '{' + ', '.join(lits) + '}'

    def _solution_score(self, solution):
        lits = self._stable_solution_literals(solution)
        cpl = sum(self._literal_complexity(lit) for lit in solution)
        return (len(solution), cpl, ' & '.join(lits))

    def _ordered_unique_solutions(self, solutions):
        uniq = {}
        for sol in solutions:
            key = tuple(self._stable_solution_literals(sol))
            if key not in uniq:
                uniq[key] = set(sol)
        return sorted(uniq.values(), key=self._solution_score)

    def _validate_ct_policy(self, selected_policy):
        if not getattr(self.args, 'ct_mode', False):
            return None
        if not hasattr(self.checkers, 'evaluate_ct_policy'):
            return None
        baseline = self.checkers.evaluate_ct_policy(set())
        selected = self.checkers.evaluate_ct_policy(set(selected_policy))
        return {
            'baseline': baseline,
            'selected': selected,
        }

    def _stats_to_dict(self):
        return {
            'core': {
                'solutions': self.stats.solutions,
                'unsolutions': self.stats.unsolutions,
                'examples': self.stats.examples,
                'counterexamples': self.stats.counterex,
                'necessary_literals': self.stats.necessaryc,
            },
            'generation': {
                'restarts': self.stats.generation.restart,
                'variables': self.stats.generation.vars,
                'literals': self.stats.generation.literals,
                'evaluated': self.stats.generation.evaluated,
                'considered': self.stats.generation.considered,
                'pruned': dict(self.stats.generation.pruned),
            },
            'oracles': {
                name: {
                    'calls': data.calls,
                    'timeouts': data.timeouts,
                    'crashes': data.crashes,
                    'times': list(data.times),
                }
                for name, data in self.stats.oracle_stats.items()
            },
            'timers': {
                name: {
                    'first': timer.first,
                    'last': timer.last,
                }
                for name, timer in self.stats.timers.items()
            },
        }

    def _semantic_post_filter_solutions(self, solutions):
        # Remove semantically redundant sufficient conditions with BINSEC
        # necessity checks (real semantics, not only syntactic subset checks).
        solutions = [set(sol) for sol in solutions]
        if len(solutions) <= 1:
            return solutions

        changed = True
        while changed and len(solutions) > 1:
            changed = False
            for idx, solution in enumerate(list(solutions)):
                trial = solutions[:idx] + solutions[idx+1:]
                if len(trial) == 0:
                    continue
                if self.check_necessity(trial):
                    self.log.debug('semantic post-filter removed: {}'.format(stringify(solution)))
                    solutions = trial
                    changed = True
                    break

        # If one solution alone is already necessary, keep that single formula.
        if len(solutions) > 1:
            singleton_necessary = [sol for sol in solutions if self.check_necessity([sol])]
            if len(singleton_necessary) > 0:
                best = min(singleton_necessary, key=lambda sol: (len(sol), len(stringify(sol))))
                self.log.debug('semantic post-filter selected singleton: {}'.format(stringify(best)))
                solutions = [best]

        return solutions

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
                    original = [set(sol) for sol in self.engine.get_solutions()]
                    general = self._semantic_post_filter_solutions(original)
                    if not self.check_necessity(general):
                        self.log.warning('semantic post-filter broke necessity; restoring original result set')
                        general = original
                    ordered = self._ordered_unique_solutions(original)
                    self.engine.storage.solutions = ordered
                    selected = ordered[0] if len(ordered) > 0 else None
                    alternatives = ordered[1:] if len(ordered) > 1 else []

                    self.log.info('obtained a necessary result set')
                    self.log.result('nas conditions (all): {}'.format(self.engine.get_stringified_solutions()))
                    if selected is not None:
                        self.log.result('general nas condition: {}'.format(self._stable_solution_string(selected)))
                        self.log.result('selected policy: {}'.format(self._stable_solution_string(selected)))
                        if len(alternatives) > 0:
                            self.log.result('alternative policies: {}'.format([self._stable_solution_string(sol) for sol in alternatives]))
                    else:
                        self.log.result('general nas condition: {}'.format([stringify(sol) for sol in general]))
                    self.result_summary['selected_policy'] = self._stable_solution_string(selected) if selected is not None else None
                    self.result_summary['alternatives'] = [self._stable_solution_string(sol) for sol in alternatives]
                    self.result_summary['nas_conditions_all'] = [self._stable_solution_string(sol) for sol in ordered]
                    self.result_summary['ct_validation'] = self._validate_ct_policy(selected) if selected is not None else None
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
        self.result_summary['stats'] = self._stats_to_dict()
        return self.result_summary
# --------------------
