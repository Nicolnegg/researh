# -------------------$
# --------------------
# --------------------
import time
import re
import itertools
from pulseutils.strings import stringify
from . import minibinsec
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
            'policy_semantics': None,
            'branch_guided_policies': [],
            'selection_mode': None,
            'selection_reason': None,
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

    def _stable_clause_string(self, solution):
        lits = self._stable_solution_literals(solution)
        if len(lits) == 0:
            return 'true'
        if len(lits) == 1:
            return lits[0]
        return '(' + ' & '.join(lits) + ')'

    def _stable_policies_or_string(self, solutions):
        if len(solutions) == 0:
            return '{}'
        if len(solutions) == 1:
            return self._stable_solution_string(solutions[0])
        return ' OR '.join(self._stable_solution_string(sol) for sol in solutions)

    def _stable_unified_condition_string(self, solutions):
        # One single set-like condition string for display/reporting.
        if len(solutions) == 0:
            return '{}'
        if len(solutions) == 1:
            return self._stable_solution_string(solutions[0])
        clauses = ['({})'.format(self._stable_clause_string(sol)) for sol in solutions]
        return '{' + ' | '.join(clauses) + '}'

    def _parse_simple_relation(self, lit_text):
        text = lit_text.strip()
        if text.startswith('(') and text.endswith(')'):
            text = text[1:-1].strip()
        m = re.match(r'^(.*?)\s(<s|=)\s(.*?)$', text)
        if m is None:
            return None
        return m.group(1).strip(), m.group(2).strip(), m.group(3).strip()

    def _compact_policy_condition(self, solutions):
        # Return a compact single-formula view when OR policies are a classic
        # partition such as (x < y) OR (x = y) -> (x <= y).
        if len(solutions) != 2:
            return None
        if any(len(sol) != 1 for sol in solutions):
            return None

        l1 = str(next(iter(solutions[0])))
        l2 = str(next(iter(solutions[1])))
        p1 = self._parse_simple_relation(l1)
        p2 = self._parse_simple_relation(l2)
        if p1 is None or p2 is None:
            return None

        # Normalize equality orientation.
        def _norm_eq(lhs, rhs):
            return tuple(sorted((lhs, rhs)))

        # Case A: (<s) OR (=) with same operand pair => <=s
        if p1[1] == '<s' and p2[1] == '=':
            if _norm_eq(p1[0], p1[2]) == _norm_eq(p2[0], p2[2]):
                return '{(' + p1[0] + ' <=s ' + p1[2] + ')}'
        if p2[1] == '<s' and p1[1] == '=':
            if _norm_eq(p2[0], p2[2]) == _norm_eq(p1[0], p1[2]):
                return '{(' + p2[0] + ' <=s ' + p2[2] + ')}'

        return None

    def _solution_score(self, solution):
        lits = self._stable_solution_literals(solution)
        cpl = sum(self._literal_complexity(lit) for lit in solution)
        return (len(solution), cpl, ' & '.join(lits))

    def _detect_primary_branch_key(self, solutions):
        # Pick a dominant (variable, constant) pair that looks like the branch pivot.
        stats = {}
        for sol in solutions:
            seen = set()
            for lit in sol:
                atom = self._extract_branch_atom(lit)
                if atom is None:
                    continue
                key = (atom[0], atom[1])  # (var, const)
                if key not in stats:
                    stats[key] = {'rels': set(), 'sols': 0, 'atoms': 0}
                stats[key]['rels'].add(atom[2])
                stats[key]['atoms'] += 1
                if key not in seen:
                    stats[key]['sols'] += 1
                    seen.add(key)
        if len(stats) == 0:
            return None
        # Prefer keys that cover several relations (<,=,>) across solutions.
        ordered = sorted(
            stats.items(),
            key=lambda kv: (-len(kv[1]['rels']), -kv[1]['sols'], -kv[1]['atoms'], kv[0][0], kv[0][1])
        )
        best_key, best_data = ordered[0]
        # Require at least two supporting solutions for robustness.
        if best_data['sols'] < 2:
            return None
        return best_key

    def _branch_first_score(self, solution, branch_key):
        lits = self._stable_solution_literals(solution)
        cpl = sum(self._literal_complexity(lit) for lit in solution)
        branch_hits = 0
        non_branch = 0
        for lit in solution:
            atom = self._extract_branch_atom(lit)
            if atom is not None and (atom[0], atom[1]) == branch_key:
                branch_hits += 1
            else:
                non_branch += 1
        has_branch = branch_hits > 0
        return (
            0 if has_branch else 1,   # branch policies first
            non_branch,               # fewer collateral literals
            len(solution),            # then simpler formulas
            cpl,
            ' & '.join(lits),
        )

    def _ordered_unique_solutions(self, solutions):
        uniq = {}
        for sol in solutions:
            key = tuple(self._stable_solution_literals(sol))
            if key not in uniq:
                uniq[key] = set(sol)
        unique_solutions = list(uniq.values())
        selected_mode = getattr(self.args, 'selection_mode', None)
        if selected_mode is None:
            selected_mode = 'branch-first' if getattr(self.args, 'ct_mode', False) else 'size-complexity'

        if selected_mode == 'branch-first':
            branch_key = None
            if getattr(self.args, 'ct_mode', False):
                branch_key = self._detect_primary_branch_key(unique_solutions)
            if branch_key is not None:
                ordered = sorted(unique_solutions, key=lambda s: self._branch_first_score(s, branch_key))
                return ordered, {
                    'mode': 'branch-first',
                    'reason': 'prioritized policies matching branch pivot {} against {}'.format(branch_key[0], branch_key[1]),
                    'branch_key': {'variable': branch_key[0], 'pivot_constant': branch_key[1]},
                }
            return sorted(unique_solutions, key=self._solution_score), {
                'mode': 'size-complexity',
                'reason': 'fallback ranking by literals count and complexity (branch pivot not robustly identified)',
                'branch_key': None,
            }

        return sorted(unique_solutions, key=self._solution_score), {
            'mode': 'size-complexity',
            'reason': 'fallback ranking by literals count and complexity',
            'branch_key': None,
        }

    def _candidate_consistent(self, candidate):
        status, _, _ = self.checkers.check_consistency(candidate)
        return bool(status)

    def _is_const_token(self, tok):
        return re.fullmatch(r'0x[0-9a-fA-F]+', tok.strip()) is not None

    def _is_mem_token(self, tok):
        return tok.strip().startswith('@[')

    def _extract_branch_atom(self, lit):
        # Return tuple (var, const, rel) where rel in {'<', '=', '>'}
        # for simple signed comparisons against constants.
        text = str(lit).strip()
        if text.startswith('(') and text.endswith(')'):
            text = text[1:-1].strip()
        m = re.match(r'^(.*?)\s(<s|=|<>)\s(.*?)$', text)
        if m is None:
            return None
        left = m.group(1).strip()
        op = m.group(2).strip()
        right = m.group(3).strip()
        if op == '<>':
            return None
        if op == '=':
            if self._is_const_token(left) and self._is_mem_token(right):
                return (right, left, '=')
            if self._is_mem_token(left) and self._is_const_token(right):
                return (left, right, '=')
            return None
        # op == <s
        if self._is_mem_token(left) and self._is_const_token(right):
            return (left, right, '<')
        if self._is_const_token(left) and self._is_mem_token(right):
            return (right, left, '>')
        return None

    def _build_policy_semantics(self, ordered):
        if len(ordered) == 0:
            return {
                'operator_between_policies': 'OR',
                'policy_ids': [],
                'selected_policy_id': None,
                'or_expression': '',
                'policies': [],
                'pairwise_compatibility': [],
                'branch_partitions': [],
            }

        pids = ['P{}'.format(i + 1) for i in range(len(ordered))]
        selected_pid = pids[0]

        policies = []
        for idx, sol in enumerate(ordered):
            policies.append({
                'id': pids[idx],
                'formula': self._stable_solution_string(sol),
                'literals': self._stable_solution_literals(sol),
                'literals_count': len(sol),
                'complexity': sum(self._literal_complexity(lit) for lit in sol),
            })

        pairwise = []
        for i, j in itertools.combinations(range(len(ordered)), 2):
            both = set(ordered[i]) | set(ordered[j])
            compatible = self._candidate_consistent(both)
            pairwise.append({
                'left': pids[i],
                'right': pids[j],
                'compatible_with_and': compatible,
                'relation': 'can_coexist' if compatible else 'mutually_exclusive',
            })

        # Detect branch-style partitions like x<k, x=k, x>k across alternative policies.
        families = {}
        for idx, sol in enumerate(ordered):
            pid = pids[idx]
            for lit in sol:
                atom = self._extract_branch_atom(lit)
                if atom is None:
                    continue
                key = (atom[0], atom[1])  # (var, const)
                if key not in families:
                    families[key] = {'<': [], '=': [], '>': []}
                families[key][atom[2]].append(pid)

        partitions = []
        for (var, cst), rels in sorted(families.items()):
            has_any = any(len(v) > 0 for v in rels.values())
            if not has_any:
                continue
            partitions.append({
                'variable': var,
                'pivot_constant': cst,
                'less_than': sorted(set(rels['<'])),
                'equal': sorted(set(rels['='])),
                'greater_than': sorted(set(rels['>'])),
                'can_merge_to_leq': len(rels['<']) > 0 and len(rels['=']) > 0,
                'can_merge_to_geq': len(rels['>']) > 0 and len(rels['=']) > 0,
            })

        return {
            'operator_between_policies': 'OR',
            'policy_ids': pids,
            'selected_policy_id': selected_pid,
            'or_expression': ' OR '.join(pids),
            'note': 'Each policy is an alternative path constraint. Do not AND all policies together.',
            'policies': policies,
            'pairwise_compatibility': pairwise,
            'branch_partitions': partitions,
        }

    def _parse_mem_token(self, token):
        m = re.match(r'^@\[(0x[0-9a-fA-F]+),([0-9]+)\]$', token.strip())
        if m is None:
            return None
        return m.group(1), int(m.group(2))

    def _evaluate_ct_terms(self, terms):
        if not getattr(self.args, 'ct_mode', False):
            return None
        if not hasattr(self.checkers, 'evaluate_ct_policy'):
            return None
        return self.checkers.evaluate_ct_policy(set(terms))

    def _derive_branch_guided_policies(self, semantics):
        # Build explicit per-branch policies for predicates var ? const:
        #   true branch:  const <s var   (var > const)
        #   false branch: (var <s const) | (var = const)  (var <= const)
        if not getattr(self.args, 'ct_mode', False):
            return []
        ctx = self.checkers.context
        guided = []
        for part in semantics.get('branch_partitions', []):
            vtok = part.get('variable')
            ctok = part.get('pivot_constant')
            mem = self._parse_mem_token(vtok or '')
            if mem is None or not ctok:
                continue
            addr, nbytes = mem
            vid = ctx.declare_var('{}:{}'.format(addr, nbytes))
            cid = ctx.declare_const(ctok)
            if ctx.get_size(vid) != ctx.get_size(cid):
                continue

            gt = ctx.create_binary_term(minibinsec.Operator.Lower, cid, vid)   # const < var
            lt = ctx.create_binary_term(minibinsec.Operator.Lower, vid, cid)   # var < const
            eq = ctx.create_binary_term(minibinsec.Operator.Equal, vid, cid)   # var = const
            leq = ctx.create_multiterm(minibinsec.Operator.Or, [lt, eq])       # var < const OR var = const

            true_terms = {gt}
            false_terms = {leq}
            st_true = self._evaluate_ct_terms(true_terms)
            st_false = self._evaluate_ct_terms(false_terms)

            guided.append({
                'variable': vtok,
                'pivot_constant': ctok,
                'true_branch': {
                    'formula': self._stable_solution_string(true_terms),
                    'meaning': '{} >s {}'.format(vtok, ctok),
                    'ct': st_true,
                },
                'false_branch': {
                    'formula': self._stable_solution_string(false_terms),
                    'meaning': '{} <=s {}'.format(vtok, ctok),
                    'ct': st_false,
                },
                'recommended_split': (
                    st_true is not None and st_false is not None and
                    st_true.get('status') == 'secure' and
                    st_false.get('status') == 'secure'
                ),
            })
        return guided

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
        clause_count = self.stats.solution_clauses if self.stats.solution_clauses > 0 else self.stats.solutions
        return {
            'core': {
                'solutions': self.stats.solutions,
                'solution_clauses': clause_count,
                'final_constraints': self.stats.final_constraints,
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

    def _finalize_nas_result(self):
        original = [set(sol) for sol in self.engine.get_solutions()]
        general = self._semantic_post_filter_solutions(original)
        if not self.check_necessity(general):
            self.log.warning('semantic post-filter broke necessity; restoring original result set')
            general = original
        ordered, selmeta = self._ordered_unique_solutions(general)
        self.engine.storage.solutions = ordered
        selected = ordered[0] if len(ordered) > 0 else None
        alternatives = ordered[1:] if len(ordered) > 1 else []
        general_expr = self._stable_policies_or_string(ordered)
        unified_expr = self._stable_unified_condition_string(ordered)
        compact_expr = self._compact_policy_condition(ordered)
        final_condition = compact_expr if compact_expr is not None else general_expr

        self.log.info('obtained a necessary result set')
        self.log.result('nas conditions (all): {}'.format(unified_expr))
        if selected is not None:
            self.log.result('selected constraint (necessary & sufficient): {}'.format(final_condition))
        else:
            self.log.result('general nas condition: {}'.format([stringify(sol) for sol in general]))

        semantics = self._build_policy_semantics(ordered)
        guided = self._derive_branch_guided_policies(semantics)
        # End-user aggregate counters: one final constraint composed of OR-clauses.
        self.stats.solution_clauses = len(ordered)
        self.stats.final_constraints = 1 if selected is not None else 0
        for gpol in guided:
            if gpol.get('recommended_split'):
                self.log.result('branch-guided split:')
                self.log.result('  true : {}'.format(gpol['true_branch']['formula']))
                self.log.result('  false: {}'.format(gpol['false_branch']['formula']))
        self.result_summary['selected_policy'] = final_condition if selected is not None else None
        self.result_summary['selected_policy_representative'] = self._stable_solution_string(selected) if selected is not None else None
        self.result_summary['selected_constraint'] = final_condition if selected is not None else None
        self.result_summary['selected_constraint_representative'] = self._stable_solution_string(selected) if selected is not None else None
        self.result_summary['policy_condition'] = general_expr
        self.result_summary['policy_condition_unified'] = unified_expr
        self.result_summary['policy_condition_compact'] = compact_expr
        self.result_summary['general_nas_condition'] = general_expr
        self.result_summary['alternatives'] = [self._stable_solution_string(sol) for sol in alternatives]
        self.result_summary['nas_conditions_all'] = [self._stable_solution_string(sol) for sol in ordered]
        self.result_summary['ct_validation'] = self._validate_ct_policy(selected) if selected is not None else None
        self.result_summary['policy_semantics'] = semantics
        self.result_summary['branch_guided_policies'] = guided
        self.result_summary['selection_mode'] = selmeta['mode']
        self.result_summary['selection_reason'] = selmeta

    def solve(self):
        self.stats.start_timers(('solution', 'unsolution', 'counterex', 'example', 'necessaryc'))
        collect_until_timeout = getattr(self.args, 'collect_until_timeout', False)
        solver_timeout = getattr(self.args, 'solver_timeout', None)
        has_timeout = solver_timeout is not None and solver_timeout > 0
        start_time = time.time()
        nas_found = False

        self.get_initital_examples()
        if self.args.const_detect:
            self.recover_necessary_constants()
        for candidate, core_candidate in self.next_candidate():
            if collect_until_timeout and has_timeout and (time.time() - start_time) >= solver_timeout:
                self.log.warning('solver timeout reached ({}s), stopping search'.format(solver_timeout))
                break
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
                    nas_found = True
                    if not collect_until_timeout:
                        self._finalize_nas_result()
                        break
                    self.log.info('necessary set found; continuing search until timeout')
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
        if nas_found and self.result_summary.get('selected_policy') is None:
            self._finalize_nas_result()
        self.result_summary['stats'] = self._stats_to_dict()
        return self.result_summary
# --------------------
