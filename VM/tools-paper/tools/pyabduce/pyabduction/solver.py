# -------------------$
# --------------------
# --------------------
import time
import re
import itertools
from pulseutils.strings import stringify
from . import minibinsec
from .ct_explain import build_ct_explain
from .ct_types import CounterexampleCT, LeakSite
# --------------------
class AbductionSolver:

    def __init__(self, args, engine, checkers, stats, logger):
        self.args = args
        self.engine = engine
        self.checkers = checkers
        self.stats = stats
        self.log = logger
        self._last_ct_refine_meta = {'minimized': False, 'widened': False}
        self.result_summary = {
            'selected_policy': None,
            'alternatives': [],
            'nas_conditions_all': [],
            'ct_validation': None,
            'baseline_status': None,
            'leak_sites': [],
            'q_safe': None,
            'q_explain': [],
            'q_explain_pivots': [],
            'policy_semantics': None,
            'branch_guided_policies': [],
            'selection_mode': None,
            'selection_reason': None,
            'ct_counterexamples': [],
            'ct_secure_clauses': [],
            'ct_insecure_evidence': [],
            'ct_dnf_policy': None,
            'ct_dnf_validation': None,
            'ct_stop_reason': None,
            'ct_unknown_checks': 0,
            'ct_saturation': {
                'attempts': 0,
                'saturated': False,
                'last_target': None,
            },
            'ct_clause_reductions': {
                'checks': 0,
                'removed_clauses': 0,
                'deduplicated': 0,
            },
            'ct_pivot_cursor': 0,
            'q_leak': None,
            'evidence': {},
            'recommendation': None,
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
        if len(lits) == 0:
            return '{true}'
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

    def _clause_to_expr(self, solution):
        lits = self._stable_solution_literals(solution)
        if len(lits) == 0:
            return self._ct_typed_true_expr()
        return ' & '.join('({})'.format(lit) for lit in lits)

    def _dnf_to_expr(self, solutions):
        if len(solutions) == 0:
            return '(0x0 = 0x1)'
        return ' | '.join('({})'.format(self._clause_to_expr(sol)) for sol in solutions)

    def _not_dnf_expr(self, solutions):
        if len(solutions) == 0:
            # Logical TRUE for empty Phi. Keep as None to avoid generating
            # untyped constants like (0x0 = 0x0) in BINSEC assumptions.
            return None
        return '!({})'.format(self._dnf_to_expr(solutions))

    def _ct_typed_true_expr(self):
        # Build a typed tautology to avoid BINSEC "Unable to infer size of 0x0".
        symbols = getattr(self.checkers, 'symbol_regions', {}) or {}

        preferred = []
        for raw in (getattr(self.args, 'ct_secret', []) or []) + (getattr(self.args, 'ct_public', []) or []):
            for token in str(raw).split(','):
                name = token.strip()
                if name:
                    preferred.append(name)
        names = preferred + [k for k in symbols.keys() if k not in preferred]
        for name in names:
            region = symbols.get(name)
            if not isinstance(region, tuple) or len(region) != 2:
                continue
            try:
                base = int(region[0])
                size = int(region[1])
            except (TypeError, ValueError):
                continue
            if size <= 0:
                continue
            mem = '@[0x{:08x},{}]'.format(base, size)
            return '({} = {})'.format(mem, mem)
        # Fallback (should be rare when symbols are present).
        return '(0x1 = 0x1)'

    def _eval_ct_expr(self, expr):
        if not getattr(self.args, 'ct_mode', False):
            return None
        if not hasattr(self.checkers, 'oracle_ct'):
            return None
        return self.checkers.oracle_ct(str(expr), formatted=True)

    def _ct_oracle_result_to_dict(self, result):
        if result is None:
            return None
        leaks = []
        for leak in getattr(result, 'leaks', []) or []:
            addr = getattr(leak, 'addr', 0)
            kind = getattr(leak, 'kind', 'other')
            leaks.append({
                'addr': '0x{:08x}'.format(addr),
                'instruction': '0x{:08x}'.format(addr),
                'kind': kind,
            })
        status_norm = str(getattr(result, 'status', 'UNKNOWN')).upper()
        return {
            'status_norm': status_norm,
            'status': status_norm.lower(),
            'leaks': leaks,
        }

    def _register_ct_secure_clause(self, clause, origin='search', minimized=False, widened=False, trace=None):
        if not isinstance(clause, (set, list, tuple)):
            return None
        clause_set = set(clause)
        lits = self._stable_solution_literals(clause_set)
        key = tuple(lits)
        trace = trace if isinstance(trace, dict) else {}
        trace_data = {
            'before': list(trace.get('before_literals', [])),
            'after_minimize': list(trace.get('after_minimize_literals', [])),
            'after_widen': list(trace.get('after_widen_literals', [])),
        }
        entries = self.result_summary.get('ct_secure_clauses', [])
        for entry in entries:
            if tuple(entry.get('clause_literals', [])) != key:
                continue
            entry['count'] = int(entry.get('count', 1)) + 1
            if entry.get('origin') != origin:
                entry['origin'] = 'mixed'
            entry['minimized'] = bool(entry.get('minimized', False) or minimized)
            entry['widened'] = bool(entry.get('widened', False) or widened)
            traces = entry.get('trace')
            if not isinstance(traces, list):
                traces = []
            if any(trace_data.values()):
                traces.append(trace_data)
            entry['trace'] = traces
            return entry.get('id')
        cid = 'C{}'.format(len(entries) + 1)
        entries.append({
            'id': cid,
            'clause_literals': lits,
            'origin': str(origin),
            'minimized': bool(minimized),
            'widened': bool(widened),
            'count': 1,
            'trace': [trace_data] if any(trace_data.values()) else [],
        })
        self.result_summary['ct_secure_clauses'] = entries
        return cid

    def _candidate_relation_infos(self, candidate):
        infos = []
        for lit in candidate:
            info = self._ct_literal_relation(lit)
            if info is None:
                continue
            info = dict(info)
            info['literal'] = lit
            infos.append(info)
        return infos

    def _vars_match(self, left_var, right_var):
        lkey = self._mem_token_key(left_var)
        rkey = self._mem_token_key(right_var)
        lbase = self._mem_token_base(left_var)
        rbase = self._mem_token_base(right_var)
        if lkey is not None and rkey is not None and lkey == rkey:
            return True
        if lbase is not None and rbase is not None and lbase == rbase:
            return True
        return False

    def _relevant_ct_pivots(self, candidate):
        pivots = self._collect_ct_pivots()
        if len(pivots) <= 0:
            one = self._pick_ct_pivot()
            return [one] if isinstance(one, dict) else []

        infos = self._candidate_relation_infos(candidate)
        cvars = [i.get('variable') for i in infos if i.get('variable') is not None]
        ranked = []
        for idx, pivot in enumerate(pivots):
            if not isinstance(pivot, dict):
                continue
            pvar = self._canonical_ct_ce_variable(pivot.get('variable'))
            if pvar is None:
                continue
            is_relevant = any(self._vars_match(pvar, cv) for cv in cvars)
            if not is_relevant and len(cvars) > 0:
                continue
            ranked.append((self._pivot_quality_key(pivot, idx), pivot))
        if len(ranked) <= 0:
            ranked = [
                (self._pivot_quality_key(p, i), p)
                for i, p in enumerate(pivots)
                if isinstance(p, dict)
            ]
        ranked.sort(key=lambda x: x[0])
        return [p for _, p in ranked]

    def _upsert_ct_insecure_evidence(self, payload):
        if not isinstance(payload, dict):
            return
        leak_kind = None
        if isinstance(payload.get('leak_site'), dict):
            leak_kind = payload['leak_site'].get('kind')
        entry = {
            'variable': payload.get('variable'),
            'relation': payload.get('relation'),
            'constant': payload.get('constant'),
            'value_lo': payload.get('value_lo'),
            'value_hi': payload.get('value_hi'),
            'source': payload.get('source'),
            'leak_kind': leak_kind,
        }
        key = (
            entry['variable'],
            entry['relation'],
            entry['constant'],
            entry['value_lo'],
            entry['value_hi'],
            entry['source'],
            entry['leak_kind'],
        )
        bucket = self.result_summary.get('ct_insecure_evidence', [])
        for cur in bucket:
            ckey = (
                cur.get('variable'),
                cur.get('relation'),
                cur.get('constant'),
                cur.get('value_lo'),
                cur.get('value_hi'),
                cur.get('source'),
                cur.get('leak_kind'),
            )
            if ckey != key:
                continue
            cur['count'] = int(cur.get('count', 1)) + 1
            return
        entry['count'] = 1
        bucket.append(entry)
        self.result_summary['ct_insecure_evidence'] = bucket

    def _sync_ct_dnf_summary(self):
        if not getattr(self.args, 'ct_mode', False):
            return
        if len(self.result_summary.get('ct_secure_clauses', [])) <= 0:
            for sol in self.engine.get_solutions():
                self._register_ct_secure_clause(sol, origin='engine', minimized=False, widened=False)
        clauses = self.result_summary.get('ct_secure_clauses', [])
        clause_sets = []
        for item in clauses:
            lits = item.get('clause_literals', [])
            clause_sets.append(set(lits))
        self.result_summary['ct_dnf_policy'] = self._dnf_to_expr(clause_sets)
        if len(clause_sets) <= 0:
            self.result_summary['ct_dnf_validation'] = None
        else:
            full_validation = self._ct_oracle_result_to_dict(
                self._eval_ct_expr(self.result_summary['ct_dnf_policy'])
            )
            if full_validation is not None and full_validation.get('status_norm') == 'UNKNOWN':
                # Fallback: validate each clause separately for a robust report.
                fallback = []
                all_secure = True
                for idx, clause in enumerate(clause_sets):
                    cexpr = self._clause_to_expr(clause)
                    cval = self._ct_oracle_result_to_dict(self._eval_ct_expr(cexpr))
                    fallback.append({
                        'id': 'C{}'.format(idx + 1),
                        'expr': cexpr,
                        'validation': cval,
                    })
                    if cval is None or cval.get('status_norm') != 'SECURE':
                        all_secure = False
                full_validation['fallback_clause_validation'] = fallback
                full_validation['fallback_status'] = 'ALL_SECURE' if all_secure else 'MIXED_OR_UNKNOWN'
            self.result_summary['ct_dnf_validation'] = full_validation

    def _ct_clause_key(self, clause):
        return tuple(self._stable_solution_literals(clause))

    def _policy_accepts_ce_side(self, clauses, ce_data, field):
        saw_unknown = False
        for clause in clauses:
            cres = self._candidate_accepts_ce_side(clause, ce_data, field)
            if cres is True:
                return True
            if cres is None:
                saw_unknown = True
        if saw_unknown:
            return None
        return False

    def _policy_blocks_ce_pair(self, clauses, ce_data):
        if not isinstance(ce_data, dict):
            return False
        if ce_data.get('value_lo') is None and ce_data.get('value_hi') is None:
            return False
        lo_acc = self._policy_accepts_ce_side(clauses, ce_data, 'value_lo')
        hi_acc = self._policy_accepts_ce_side(clauses, ce_data, 'value_hi')
        # Conservative: only claim coverage when both sides are decidable.
        if lo_acc is None or hi_acc is None:
            return False
        return not (lo_acc is True and hi_acc is True)

    def _drop_redundant_ct_clauses(self, clauses, e_insec=None):
        if len(clauses) <= 1:
            return list(clauses)
        reduction_stats = self.result_summary.get('ct_clause_reductions')
        if not isinstance(reduction_stats, dict):
            reduction_stats = {'checks': 0, 'removed_clauses': 0, 'deduplicated': 0}
            self.result_summary['ct_clause_reductions'] = reduction_stats
        ordered = []
        seen = set()
        dedup_removed = 0
        for clause in clauses:
            key = self._ct_clause_key(clause)
            if key in seen:
                dedup_removed += 1
                continue
            seen.add(key)
            ordered.append(set(clause))
        if dedup_removed > 0:
            reduction_stats['deduplicated'] = int(reduction_stats.get('deduplicated', 0)) + dedup_removed
            reduction_stats['removed_clauses'] = int(reduction_stats.get('removed_clauses', 0)) + dedup_removed
        ce_pool = e_insec if isinstance(e_insec, list) else self.result_summary.get('ct_counterexamples', [])
        changed = True
        removed_redundant = 0
        while changed and len(ordered) > 1:
            changed = False
            for idx in range(len(ordered)):
                reduction_stats['checks'] = int(reduction_stats.get('checks', 0)) + 1
                trial = ordered[:idx] + ordered[idx + 1:]
                clause = [ordered[idx]]
                covered_by_clause = [ce for ce in ce_pool if self._policy_blocks_ce_pair(clause, ce)]
                if len(covered_by_clause) <= 0:
                    continue
                if not all(self._policy_blocks_ce_pair(trial, ce) for ce in covered_by_clause):
                    continue
                ordered = trial
                changed = True
                removed_redundant += 1
                break
        if removed_redundant > 0:
            reduction_stats['removed_clauses'] = int(reduction_stats.get('removed_clauses', 0)) + removed_redundant
        return ordered

    def _drop_redundant_clauses(self, s_set, e_insec=None):
        # Clause-level necessity (4.2): keep only clauses needed by the OR.
        return self._drop_redundant_ct_clauses(s_set, e_insec=e_insec)

    def _ct_saturation_check(self, clauses, start_time=None, solver_timeout=None, attempts=12, e_insec=None):
        target_expr = self._not_dnf_expr(clauses)
        checked = 0
        visited = 0
        visited_limit = max(30, int(attempts) * 20)
        for candidate, _core_candidate in self.next_candidate():
            visited += 1
            if solver_timeout is not None and start_time is not None:
                if (time.time() - start_time) >= solver_timeout:
                    return True
            if visited > visited_limit:
                break
            cand = set(candidate)
            if not self._candidate_consistent(cand):
                continue
            acceptable, _ = self._ct_candidate_acceptable(cand, e_insec=e_insec)
            if not acceptable:
                continue
            clause_expr = self._clause_to_expr(cand)
            q2_expr = clause_expr if target_expr is None else '({}) & ({})'.format(clause_expr, target_expr)
            res = self._eval_ct_expr(q2_expr)
            if res is not None and res.status == 'SECURE':
                return False
            checked += 1
            if checked >= max(1, int(attempts)):
                break
        return True

    def _saturation_check(self, phi_clauses, start_time=None, solver_timeout=None, attempts=12, e_insec=None):
        # Try T searches in NOT(Phi); if none are SECURE, policy is saturated.
        sat = self.result_summary.get('ct_saturation')
        if not isinstance(sat, dict):
            sat = {'attempts': 0, 'saturated': False, 'last_target': None}
            self.result_summary['ct_saturation'] = sat
        sat['attempts'] = int(sat.get('attempts', 0)) + 1
        sat['last_target'] = self._not_dnf_expr(phi_clauses)
        saturated = self._ct_saturation_check(
            phi_clauses,
            start_time=start_time,
            solver_timeout=solver_timeout,
            attempts=attempts,
            e_insec=e_insec,
        )
        sat['saturated'] = bool(saturated)
        return saturated

    def _ct_clause_scan_budget(self):
        # Internal safety budget so CT-DNF always terminates even without
        # --solver-timeout. Keep small defaults for interactive runs.
        base = 180
        if getattr(self.args, 'with_bitwise_terms', False):
            base += 120
        if getattr(self.args, 'with_mul_terms', False):
            base += 80
        depth = int(getattr(self.args, 'max_depth', 0) or 0)
        if depth > 0:
            base += min(200, depth * 40)
        return int(max(120, base))

    def _find_one_safe_clause(self, target_expr, e_insec=None, existing_clause_keys=None, seen_solution_keys=None, start_time=None, solver_timeout=None, max_scan=0):
        scanned = 0
        visited = 0
        existing_clause_keys = existing_clause_keys if isinstance(existing_clause_keys, set) else set()
        seen_solution_keys = seen_solution_keys if isinstance(seen_solution_keys, set) else set()
        for candidate, _core_candidate in self.next_candidate():
            visited += 1
            if solver_timeout is not None and start_time is not None:
                if (time.time() - start_time) >= solver_timeout:
                    self.result_summary['ct_stop_reason'] = 'timeout'
                    return None
            if max_scan and visited > int(max_scan):
                self.log.info('ct target search budget reached ({} candidates scanned)'.format(max_scan))
                return None
            cand = set(candidate)
            self.log.debug('trying candidate (ct-dnf): {}'.format(cand))
            if self._ct_clause_key(cand) in existing_clause_keys:
                self.log.debug('candidate skipped (already in S_set)')
                continue
            if self._ct_clause_key(cand) in seen_solution_keys:
                self.log.debug('candidate skipped (already seen globally)')
                continue
            if not self._candidate_consistent(cand):
                self.log.debug('candidate is inconsistent')
                continue
            acceptable, ce_data = self._ct_candidate_acceptable(cand, e_insec=e_insec)
            if not acceptable:
                self.stats.generation.pruned['ct_counterexample'] += 1
                self.log.debug('candidate pruned by ct CE: pivot={} values=({}, {})'.format(
                    ce_data.get('pivot'),
                    ce_data.get('value_lo'),
                    ce_data.get('value_hi'),
                ))
                continue
            clause_expr = self._clause_to_expr(cand)
            q2_expr = clause_expr if target_expr is None else '({}) & ({})'.format(clause_expr, target_expr)
            self.log.info('evaluating candidate (ct target): {}'.format(cand))
            self.stats.generation.evaluated += 1
            res = self._eval_ct_expr(q2_expr)
            if res is None:
                continue
            if res.status == 'SECURE':
                return cand
            elif res.status == 'INSECURE':
                if self._is_useful_ct_model(getattr(res, 'model', None)):
                    model = dict(res.model)
                    self.log.info('counter-example (oracle): {}'.format(model))
                    self.engine.add_counter_example(model)
                    self._record_ct_counterexample('oracle', oracle_model=model)
                else:
                    dce = self._record_ct_counterexample('derived')
                    self.engine.add_counter_example({'*controlled': set()})
                    self.log.info(
                        'counter-example (derived): pivot={} values=({}, {})'.format(
                            dce.pivot, dce.value_lo, dce.value_hi
                        )
                    )
            else:
                self.log.debug('ct oracle returned UNKNOWN for candidate')
                self.result_summary['ct_unknown_checks'] = int(self.result_summary.get('ct_unknown_checks', 0)) + 1
            scanned += 1
            if max_scan and scanned >= int(max_scan):
                break
        return None

    def _finalize_ct_dnf_result(self, clauses):
        ordered, selmeta = self._ordered_unique_solutions([set(sol) for sol in clauses])
        self.engine.storage.solutions = ordered
        selected = ordered[0] if len(ordered) > 0 else None
        alternatives = ordered[1:] if len(ordered) > 1 else []
        phi_expr = self._dnf_to_expr(ordered)
        general_expr = self._stable_policies_or_string(ordered)
        unified_expr = self._stable_unified_condition_string(ordered)
        compact_expr = self._compact_policy_condition(ordered)
        display_expr = compact_expr if compact_expr is not None else unified_expr
        final_condition = compact_expr if compact_expr is not None else general_expr
        selected_policy_expr = phi_expr if len(ordered) > 1 else (final_condition if selected is not None else None)

        self.log.info('ct dnf collection finished')
        self.log.result('secure clauses (all): {}'.format(display_expr))
        if selected_policy_expr is not None:
            self.log.result('selected constraint: {}'.format(selected_policy_expr))

        self.stats.solution_clauses = len(ordered)
        self.stats.final_constraints = 1 if selected is not None else 0
        self.result_summary['selected_policy'] = selected_policy_expr
        self.result_summary['selected_policy_representative'] = selected_policy_expr
        self.result_summary['selected_constraint'] = selected_policy_expr
        self.result_summary['selected_constraint_representative'] = selected_policy_expr
        self.result_summary['policy_condition'] = general_expr
        self.result_summary['policy_condition_unified'] = display_expr
        self.result_summary['policy_condition_compact'] = compact_expr
        self.result_summary['ct_dnf_policy'] = phi_expr
        self.result_summary['general_nas_condition'] = None
        self.result_summary['alternatives'] = [self._stable_solution_string(sol) for sol in alternatives]
        self.result_summary['nas_conditions_all'] = [self._stable_solution_string(sol) for sol in ordered]
        self.result_summary['ct_dnf_validation'] = self._ct_oracle_result_to_dict(self._eval_ct_expr(phi_expr)) if len(ordered) > 0 else None
        if len(ordered) > 1:
            self.result_summary['ct_validation'] = self.result_summary.get('ct_dnf_validation')
        else:
            self.result_summary['ct_validation'] = self._validate_ct_policy(selected) if selected is not None else None
        self.result_summary['policy_semantics'] = self._build_policy_semantics(ordered)
        self.result_summary['branch_guided_policies'] = self._derive_branch_guided_policies(self.result_summary['policy_semantics'])
        self.result_summary['selection_mode'] = 'ct-dnf'
        self.result_summary['selection_reason'] = {
            'mode': 'ct-dnf',
            'reason': 'collected multiple secure clauses under target=NOT(Phi) with redundancy drop',
            'inner_ranking': selmeta,
        }

    def _solve_ct_dnf(self, start_time, has_timeout, solver_timeout, max_solutions):
        max_clauses = int(max_solutions) if (max_solutions is not None and max_solutions > 0) else 3
        clause_scan_budget = self._ct_clause_scan_budget()
        secure_clauses = []
        seen_solution_keys = set()
        no_progress_iters = 0
        no_progress_limit = 4
        self.result_summary['ct_saturation'] = {
            'attempts': 0,
            'saturated': False,
            'last_target': None,
        }

        self.get_initital_examples()
        if self.args.const_detect:
            self.recover_necessary_constants()

        while True:
            if has_timeout and (time.time() - start_time) >= solver_timeout:
                self.log.warning('solver timeout reached ({}s), stopping ct dnf search'.format(solver_timeout))
                self.result_summary['ct_stop_reason'] = 'timeout'
                self.result_summary['ct_saturation']['saturated'] = False
                break
            if len(secure_clauses) >= max_clauses:
                self.log.info('ct dnf max clauses reached ({})'.format(max_clauses))
                self.result_summary['ct_stop_reason'] = 'max_clauses'
                self.result_summary['ct_saturation']['saturated'] = False
                break

            target_expr = self._not_dnf_expr(secure_clauses)
            self.log.debug('ct dnf target: {}'.format(target_expr))
            before_signature = tuple(sorted(self._ct_clause_key(c) for c in secure_clauses))
            clause = self._find_one_safe_clause(
                target_expr,
                e_insec=self.result_summary.get('ct_counterexamples', []),
                existing_clause_keys={self._ct_clause_key(c) for c in secure_clauses},
                seen_solution_keys=seen_solution_keys,
                start_time=start_time,
                solver_timeout=(solver_timeout if has_timeout else None),
                max_scan=clause_scan_budget,
            )
            if clause is None:
                stop_reason = self.result_summary.get('ct_stop_reason') or 'saturated'
                self.result_summary['ct_stop_reason'] = stop_reason
                self.result_summary['ct_saturation']['saturated'] = (stop_reason == 'saturated')
                break

            refined = self._ct_refine_secure_candidate(clause)
            if refined != clause:
                self.log.debug('ct refine secure candidate: {} -> {}'.format(clause, refined))
            seen_solution_keys.add(self._ct_clause_key(clause))
            seen_solution_keys.add(self._ct_clause_key(refined))
            self.log.result('satisfying solution: {}'.format(stringify(refined)))
            self.store_solution(set(refined), None)
            self._register_ct_secure_clause(
                refined,
                origin='search',
                minimized=bool(self._last_ct_refine_meta.get('minimized', False)),
                widened=bool(self._last_ct_refine_meta.get('widened', False)),
                trace=self._last_ct_refine_meta,
            )

            key = self._ct_clause_key(refined)
            if key not in {self._ct_clause_key(c) for c in secure_clauses}:
                secure_clauses.append(set(refined))

            # Clear 4.1 vs 4.2 rule:
            # - |S_set| == 1: only literal minimization (4.1)
            # - |S_set| >= 2: 4.1 on each clause, then global clause necessity (4.2)
            if len(secure_clauses) == 1:
                secure_clauses = [self._ct_minimize_candidate(secure_clauses[0])]
            else:
                secure_clauses = [self._ct_minimize_candidate(clause) for clause in secure_clauses]
                secure_clauses = self._drop_redundant_clauses(
                    secure_clauses,
                    e_insec=self.result_summary.get('ct_counterexamples', []),
                )

            self.engine.storage.solutions = [set(c) for c in secure_clauses]
            self._sync_ct_dnf_summary()
            after_signature = tuple(sorted(self._ct_clause_key(c) for c in secure_clauses))
            if after_signature == before_signature:
                no_progress_iters += 1
                self.log.info('ct dnf no-progress iteration ({}/{})'.format(no_progress_iters, no_progress_limit))
            else:
                no_progress_iters = 0
            if no_progress_iters >= no_progress_limit:
                self.result_summary['ct_stop_reason'] = 'saturated'
                self.result_summary['ct_saturation']['saturated'] = True
                break

            if len(secure_clauses) > 0 and self._saturation_check(
                secure_clauses,
                start_time=start_time,
                solver_timeout=(solver_timeout if has_timeout else None),
                attempts=10,
                e_insec=self.result_summary.get('ct_counterexamples', []),
            ):
                self.result_summary['ct_stop_reason'] = 'saturated'
                self.result_summary['ct_saturation']['saturated'] = True
                break

        if len(secure_clauses) > 0:
            self._finalize_ct_dnf_result(secure_clauses)
        else:
            qex = self.result_summary.get('q_explain') or []
            if qex:
                self.log.warning('no secure policy found within budget; returning q_explain guidance')
                self.log.result('q_explain (fallback): {}'.format(qex))
            if self.result_summary.get('ct_stop_reason') is None:
                self.result_summary['ct_stop_reason'] = 'saturated'

    def _parse_simple_relation(self, lit_text):
        text = lit_text.strip()
        if text.startswith('(') and text.endswith(')'):
            text = text[1:-1].strip()
        m = re.match(r'^(.*?)\s(<s|<=s|>=s|>s|<u|<=u|>=u|>u|=|<>)\s(.*?)$', text)
        if m is None:
            return None
        return m.group(1).strip(), m.group(2).strip(), m.group(3).strip()

    def _mem_token_bits(self, tok):
        m = re.match(r'^@\[(0x[0-9a-fA-F]+),([0-9]+)\]$', tok.strip())
        if m is None:
            return None
        try:
            return int(m.group(2)) * 8
        except ValueError:
            return None

    def _mem_token_key(self, tok):
        m = re.match(r'^@\[(0x[0-9a-fA-F]+),([0-9]+)\]$', str(tok).strip())
        if m is None:
            return None
        try:
            return int(m.group(1), 16), int(m.group(2))
        except ValueError:
            return None

    def _mem_token_base(self, tok):
        key = self._mem_token_key(tok)
        if key is None:
            return None
        return key[0]

    def _signed_const_value(self, tok, bits):
        if bits is None or bits <= 0:
            return None
        try:
            raw = int(tok, 0)
        except ValueError:
            return None
        mask = (1 << bits) - 1
        raw &= mask
        sign = 1 << (bits - 1)
        if raw & sign:
            raw -= (1 << bits)
        return raw

    def _single_clause_atom(self, solution):
        if len(solution) != 1:
            return None
        lit = next(iter(solution))
        atom = self._extract_branch_atom(lit)
        if atom is not None:
            var, cst, rel = atom
            bits = self._mem_token_bits(var)
            sval = self._signed_const_value(cst, bits)
            return {'var': var, 'const': cst, 'rel': rel, 'bits': bits, 'sval': sval}

        parsed = self._parse_simple_relation(str(lit))
        if parsed is None:
            return None
        left, op, right = parsed
        if op == '<>':
            if self._is_const_token(left) and self._is_mem_token(right):
                var, cst = right, left
            elif self._is_mem_token(left) and self._is_const_token(right):
                var, cst = left, right
            else:
                return None
            bits = self._mem_token_bits(var)
            sval = self._signed_const_value(cst, bits)
            return {'var': var, 'const': cst, 'rel': '!=', 'bits': bits, 'sval': sval}
        return None

    def _compact_policy_condition(self, solutions):
        # Return a compact single-formula view when OR policies are a classic
        # partition such as (x < y) OR (x = y) -> (x <= y).
        if len(solutions) == 0:
            return None

        atoms = []
        for sol in solutions:
            atom = self._single_clause_atom(sol)
            if atom is None:
                return None
            atoms.append(atom)

        # Only compact single-variable OR families.
        vars_seen = {a['var'] for a in atoms}
        if len(vars_seen) != 1:
            return None
        vtok = atoms[0]['var']

        # Drop exact duplicates.
        uniq = {}
        for a in atoms:
            uniq[(a['rel'], a['const'])] = a
        atoms = list(uniq.values())

        if len(atoms) == 1:
            a = atoms[0]
            if a['rel'] == '<':
                return '{(' + vtok + ' <s ' + a['const'] + ')}'
            if a['rel'] == '>':
                return '{(' + a['const'] + ' <s ' + vtok + ')}'
            if a['rel'] == '=':
                return '{(' + vtok + ' = ' + a['const'] + ')}'
            if a['rel'] == '!=':
                return '{(' + vtok + ' <> ' + a['const'] + ')}'
            return None

        rels = {a['rel'] for a in atoms}
        by_rel = {}
        for a in atoms:
            by_rel.setdefault(a['rel'], []).append(a)

        # Single-sided OR simplification on thresholds.
        if rels == {'<'}:
            best = max(by_rel['<'], key=lambda a: (a['sval'] is not None, a['sval']))
            return '{(' + vtok + ' <s ' + best['const'] + ')}'
        if rels == {'>'}:
            best = min(by_rel['>'], key=lambda a: (a['sval'] is None, a['sval']))
            return '{(' + best['const'] + ' <s ' + vtok + ')}'
        if rels == {'='}:
            if len(by_rel['=']) == 1:
                return '{(' + vtok + ' = ' + by_rel['='][0]['const'] + ')}'
            return None
        if rels == {'!='}:
            if len(by_rel['!=']) == 1:
                return '{(' + vtok + ' <> ' + by_rel['!='][0]['const'] + ')}'
            return None

        # Pairwise same-pivot merges.
        if rels == {'<', '='} and len(by_rel['<']) == 1 and len(by_rel['=']) == 1:
            if by_rel['<'][0]['const'] == by_rel['='][0]['const']:
                return '{(' + vtok + ' <=s ' + by_rel['<'][0]['const'] + ')}'
        if rels == {'>', '='} and len(by_rel['>']) == 1 and len(by_rel['=']) == 1:
            if by_rel['>'][0]['const'] == by_rel['='][0]['const']:
                return '{(' + vtok + ' >=s ' + by_rel['>'][0]['const'] + ')}'
        if rels == {'<', '>'} and len(by_rel['<']) == 1 and len(by_rel['>']) == 1:
            if by_rel['<'][0]['const'] == by_rel['>'][0]['const']:
                return '{(' + vtok + ' <> ' + by_rel['<'][0]['const'] + ')}'

        # Generic fallback for var-vs-var formulas where _extract_branch_atom
        # is intentionally not used (it focuses on var-vs-constant pivots).
        if len(solutions) == 2 and all(len(sol) == 1 for sol in solutions):
            l1 = str(next(iter(solutions[0])))
            l2 = str(next(iter(solutions[1])))
            p1 = self._parse_simple_relation(l1)
            p2 = self._parse_simple_relation(l2)
            if p1 is not None and p2 is not None:
                def _norm_pair(a, b):
                    return tuple(sorted((a, b)))

                # (<s) OR (=) on same pair => <=s
                if p1[1] == '<s' and p2[1] == '=' and _norm_pair(p1[0], p1[2]) == _norm_pair(p2[0], p2[2]):
                    return '{(' + p1[0] + ' <=s ' + p1[2] + ')}'
                if p2[1] == '<s' and p1[1] == '=' and _norm_pair(p2[0], p2[2]) == _norm_pair(p1[0], p1[2]):
                    return '{(' + p2[0] + ' <=s ' + p2[2] + ')}'

                # (x < y) OR (y < x) => x <> y
                if p1[1] == '<s' and p2[1] == '<s' and p1[0] == p2[2] and p1[2] == p2[0]:
                    return '{(' + p1[0] + ' <> ' + p1[2] + ')}'

        return None

    def _solution_score(self, solution):
        lits = self._stable_solution_literals(solution)
        cpl = sum(self._literal_complexity(lit) for lit in solution)
        if getattr(self.args, 'ct_mode', False):
            eqc, ineqc, bwc = self._ct_generality_stats(solution)
            return (
                self._pivot_boost_rank(solution),
                eqc,          # fewer singleton equalities first
                -ineqc,       # more ranges first
                bwc,          # simpler/non-bitwise first
                len(solution),
                cpl,
                ' & '.join(lits),
            )
        return (self._pivot_boost_rank(solution), len(solution), cpl, ' & '.join(lits))

    def _ct_generality_stats(self, solution):
        eq_const = 0
        ineq = 0
        bitwise = 0
        for lit in solution:
            txt = str(lit)
            if any(tok in txt for tok in ('&', '|', '~', '<<', '>>', '::')):
                bitwise += 1
            parsed = self._parse_relation_literal(txt)
            if parsed is None:
                continue
            left = parsed['left']
            right = parsed['right']
            op = parsed['op']
            left_is_mem = self._mem_token_key(left) is not None
            right_is_mem = self._mem_token_key(right) is not None
            left_is_const = self._is_const_token(left)
            right_is_const = self._is_const_token(right)
            if op == '=' and ((left_is_mem and right_is_const) or (right_is_mem and left_is_const)):
                eq_const += 1
            if op in {'<s', '<=s', '>s', '>=s', '<u', '<=u', '>u', '>=u'}:
                ineq += 1
        return eq_const, ineq, bitwise

    def _literal_int_constants(self, text):
        vals = set()
        for tok in re.findall(r'-?(?:0x[0-9a-fA-F]+|[0-9]+)', str(text)):
            try:
                vals.add(int(tok, 0))
            except ValueError:
                continue
        return vals

    def _pivot_boost_rank(self, solution):
        if not getattr(self.args, 'ct_mode', False):
            return 1
        pivots = self.result_summary.get('q_explain_pivots') or []
        if not pivots and hasattr(self.checkers, 'ct_explain_pivots'):
            pivots = getattr(self.checkers, 'ct_explain_pivots', []) or []
        if not pivots:
            return 1

        lit_texts = [str(lit) for lit in solution]
        lit_consts = [self._literal_int_constants(txt) for txt in lit_texts]

        for pivot in pivots:
            if not isinstance(pivot, dict):
                continue
            pred = str(pivot.get('predicate', '')).strip()
            if pred and any((pred in txt) or (txt in pred) for txt in lit_texts):
                return 0

            pvar = self._canonical_ct_ce_variable(pivot.get('variable'))
            pcst = self._parse_int_token(pivot.get('constant'))
            if not pvar:
                continue
            for idx, txt in enumerate(lit_texts):
                if pvar not in txt:
                    continue
                if pcst is None:
                    return 0
                if pcst in lit_consts[idx]:
                    return 0
        return 1

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
        eqc, ineqc, bwc = self._ct_generality_stats(solution)
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
            self._pivot_boost_rank(solution),  # q_explain-pivot policies first
            0 if has_branch else 1,   # branch policies first
            non_branch,               # fewer collateral literals
            eqc,                      # prefer ranges to equalities
            -ineqc,
            bwc,
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
        # Single ranking strategy:
        # - In CT mode, first try branch-aware ordering.
        # - Otherwise (or when pivot is unclear), fallback to size/complexity.
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

    def _candidate_consistent(self, candidate):
        status, _, _ = self.checkers.check_consistency(candidate)
        return bool(status)

    def _is_const_token(self, tok):
        return re.fullmatch(r'-?(0x[0-9a-fA-F]+|[0-9]+)', tok.strip()) is not None

    def _is_mem_token(self, tok):
        return tok.strip().startswith('@[')

    def _extract_branch_atom(self, lit):
        # Return tuple (var, const, rel) where rel in {'<', '=', '>'}
        # for simple signed comparisons against constants.
        text = str(lit).strip()
        if text.startswith('(') and text.endswith(')'):
            text = text[1:-1].strip()
        m = re.match(r'^(.*?)\s(<s|<=s|>s|>=s|<u|<=u|>u|>=u|=|<>)\s(.*?)$', text)
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
        if op in {'<s', '<=s', '<u', '<=u'}:
            if self._is_mem_token(left) and self._is_const_token(right):
                return (left, right, '<')
            if self._is_const_token(left) and self._is_mem_token(right):
                return (right, left, '>')
            return None
        if op in {'>s', '>=s', '>u', '>=u'}:
            if self._is_mem_token(left) and self._is_const_token(right):
                return (left, right, '>')
            if self._is_const_token(left) and self._is_mem_token(right):
                return (right, left, '<')
            return None
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
        if not hasattr(self.checkers, 'context'):
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

    def _format_leak_sites(self, leaks):
        result = []
        for leak in leaks or []:
            addr = getattr(leak, 'addr', 0)
            kind = getattr(leak, 'kind', 'other')
            result.append({
                'addr': '0x{:08x}'.format(addr),
                'kind': kind,
            })
        return result

    def _build_ct_explain(self, leaks):
        if not getattr(self.args, 'ct_mode', False):
            return [], []
        binary = getattr(self.checkers, 'binary', None)
        if not binary:
            return [], []
        try:
            data = build_ct_explain(binary, leaks)
        except Exception as ex:
            self.log.warning('ct explain extraction failed: {}'.format(ex))
            return [], []
        q_explain = data.get('q_explain', [])
        pivots = data.get('pivots', [])
        if q_explain:
            self.log.result('q_explain (prioritized): {}'.format(q_explain))
        return q_explain, pivots

    def _is_useful_ct_model(self, model):
        if not isinstance(model, dict):
            return False
        for key in model.keys():
            skey = str(key)
            if skey != 'default' and not skey.startswith('*'):
                return True
        return False

    def _pivot_quality_key(self, pivot, index=0):
        if not isinstance(pivot, dict):
            return (9, 9, 9, index)
        rel = str(pivot.get('relation', '')).strip()
        leak_kind = str(pivot.get('leak_kind', pivot.get('kind', 'other'))).strip().lower()
        cst = self._parse_int_token(pivot.get('constant'))
        # Prefer memory-access pivots over control-flow pivots.
        if leak_kind == 'memory_access':
            lk = 0
        elif leak_kind == 'control_flow':
            lk = 1
        else:
            lk = 2
        # Prefer branch-like range pivots over equality/disequality:
        #   <,<=,>,>=  then =  then <>.
        if rel in {'<s', '<u', '<=s', '<=u', '>s', '>u', '>=s', '>=u'}:
            rr = 0
        elif rel == '=':
            rr = 1
        elif rel == '<>':
            rr = 2
        else:
            rr = 3
        has_const = 0 if cst is not None else 1
        return (lk, rr, has_const, index)

    def _collect_ct_pivots(self):
        pivots = []
        qexp_pivots = self.result_summary.get('q_explain_pivots') or []
        if not qexp_pivots and hasattr(self.checkers, 'ct_explain_pivots'):
            qexp_pivots = getattr(self.checkers, 'ct_explain_pivots', []) or []
        for pivot in qexp_pivots:
            if not isinstance(pivot, dict):
                continue
            pivots.append(dict(pivot))

        # Reuse accumulated insecure evidence as extra pivot candidates.
        for ev in self.result_summary.get('ct_insecure_evidence', []):
            if not isinstance(ev, dict):
                continue
            var = ev.get('variable')
            rel = ev.get('relation')
            cst = ev.get('constant')
            if var is None or rel is None or cst is None:
                continue
            p = {
                'predicate': ev.get('pivot') or '({} {} {})'.format(var, rel, cst),
                'variable': var,
                'relation': rel,
                'constant': cst,
                'leak_kind': ev.get('leak_kind', 'other'),
            }
            pivots.append(p)

        dedup = []
        seen = set()
        for p in pivots:
            key = (
                str(p.get('variable')),
                str(p.get('relation')),
                str(p.get('constant')),
                str(p.get('leak_kind', p.get('kind', 'other'))),
            )
            if key in seen:
                continue
            seen.add(key)
            dedup.append(p)
        return dedup

    def _pick_ct_pivot(self, rotate=False):
        pivots = self._collect_ct_pivots()
        if not pivots:
            return None
        ranked = []
        for idx, piv in enumerate(pivots):
            if not isinstance(piv, dict):
                continue
            ranked.append((self._pivot_quality_key(piv, idx), piv))
        if not ranked:
            first = pivots[0]
            return first if isinstance(first, dict) else None
        ranked.sort(key=lambda x: x[0])
        if not rotate:
            return ranked[0][1]
        cursor = int(self.result_summary.get('ct_pivot_cursor', 0) or 0)
        pick = ranked[cursor % len(ranked)][1]
        self.result_summary['ct_pivot_cursor'] = cursor + 1
        return pick

    def _parse_int_token(self, value):
        if value is None:
            return None
        try:
            return int(str(value), 0)
        except ValueError:
            return None

    def _ct_pivot_values(self, pivot):
        if not isinstance(pivot, dict):
            return 0, 1
        relation = str(pivot.get('relation', '')).strip()
        cst = self._parse_int_token(pivot.get('constant'))
        if cst is None:
            return 0, 1
        # Pick one value on each side of the decision boundary.
        # Strict relations split exactly at cst; non-strict split at cst +/- 1.
        if relation in {'<s', '<u'}:
            return cst - 1, cst
        if relation in {'<=s', '<=u'}:
            return cst, cst + 1
        if relation in {'>s', '>u'}:
            return cst, cst + 1
        if relation in {'>=s', '>=u'}:
            return cst - 1, cst
        if relation in {'=', '<>'}:
            return cst, cst + 1
        return cst, cst + 1

    def _canonical_ct_ce_variable(self, raw_variable):
        if raw_variable is not None and self._mem_token_key(raw_variable) is not None:
            return str(raw_variable).strip()
        symbols = getattr(self.checkers, 'symbol_regions', {}) or {}
        secret_names = []
        for raw in getattr(self.args, 'ct_secret', []) or []:
            for token in str(raw).split(','):
                name = token.strip()
                if name:
                    secret_names.append(name)
        candidates = []
        for name, region in symbols.items():
            if not isinstance(region, tuple) or len(region) != 2:
                continue
            if secret_names:
                if name not in secret_names:
                    continue
            else:
                if not (str(name).startswith('secret_') or str(name).startswith('__VERIFIER_nondet_slot')):
                    continue
            base, size = region
            try:
                candidates.append((int(base), int(size)))
            except (TypeError, ValueError):
                continue
        if len(candidates) == 1:
            base, size = candidates[0]
            return '@[0x{:08x},{}]'.format(base, size)
        return str(raw_variable).strip() if raw_variable is not None else None

    def _default_ct_leak_site(self):
        leaks = self.result_summary.get('leak_sites') or []
        if len(leaks) <= 0:
            return None
        first = leaks[0]
        if not isinstance(first, dict):
            return None
        try:
            addr = int(str(first.get('addr', '0x0')), 0)
        except ValueError:
            addr = 0
        kind = str(first.get('kind', 'other'))
        return LeakSite(addr=addr, kind=kind)

    def _build_ct_counterexample(self, source, oracle_model=None):
        # Always rotate through ranked pivots to avoid permanent first-pivot bias.
        pivot = self._pick_ct_pivot(rotate=True)
        pred = pivot.get('predicate') if isinstance(pivot, dict) else None
        raw_var = pivot.get('variable') if isinstance(pivot, dict) else None
        pvar = self._canonical_ct_ce_variable(raw_var)
        prel = pivot.get('relation') if isinstance(pivot, dict) else None
        pcst = pivot.get('constant') if isinstance(pivot, dict) else None
        vlo = None
        vhi = None
        if source == 'derived':
            vlo, vhi = self._ct_pivot_values(pivot)
        cex = CounterexampleCT(
            pivot=pred,
            value_lo=vlo,
            value_hi=vhi,
            leak_site=self._default_ct_leak_site(),
            source=source,
        )
        payload = {
            'source': source,
            'pivot': cex.pivot,
            'variable': pvar,
            'relation': prel,
            'constant': pcst,
            'value_lo': cex.value_lo,
            'value_hi': cex.value_hi,
        }
        if cex.leak_site is not None:
            payload['leak_site'] = {
                'addr': '0x{:08x}'.format(cex.leak_site.addr),
                'kind': cex.leak_site.kind,
            }
        if source == 'oracle' and isinstance(oracle_model, dict):
            payload['oracle_model'] = dict(oracle_model)
        return cex, payload

    def _record_ct_counterexample(self, source, oracle_model=None):
        cex, payload = self._build_ct_counterexample(source, oracle_model=oracle_model)
        self.result_summary['ct_counterexamples'].append(payload)
        self._upsert_ct_insecure_evidence(payload)
        return cex

    def _parse_relation_literal(self, lit_text):
        text = lit_text.strip()
        while text.startswith('(') and text.endswith(')'):
            inner = text[1:-1].strip()
            if inner.count('(') != inner.count(')'):
                break
            text = inner
        m = re.match(r'^(.*?)\s(<s|<=s|>=s|>s|<u|<=u|>=u|>u|=|<>)\s(.*?)$', text)
        if m is None:
            return None
        return {
            'left': m.group(1).strip(),
            'op': m.group(2).strip(),
            'right': m.group(3).strip(),
        }

    def _invert_relation(self, op):
        inv = {
            '<s': '>s',
            '<=s': '>=s',
            '>s': '<s',
            '>=s': '<=s',
            '<u': '>u',
            '<=u': '>=u',
            '>u': '<u',
            '>=u': '<=u',
            '=': '=',
            '<>': '<>',
        }
        return inv.get(op)

    def _normalize_cmp_value(self, val, bits, signed):
        if bits is None or bits <= 0:
            bits = 32
        mask = (1 << bits) - 1
        val &= mask
        if signed:
            sign = 1 << (bits - 1)
            if val & sign:
                val -= (1 << bits)
        return val

    def _compare_rel(self, lhs, rhs, op, bits):
        if op in {'=','<>'}:
            if op == '=':
                return lhs == rhs
            return lhs != rhs
        signed = op.endswith('s')
        lhsn = self._normalize_cmp_value(lhs, bits, signed)
        rhsn = self._normalize_cmp_value(rhs, bits, signed)
        if op in {'<s', '<u'}:
            return lhsn < rhsn
        if op in {'<=s', '<=u'}:
            return lhsn <= rhsn
        if op in {'>s', '>u'}:
            return lhsn > rhsn
        if op in {'>=s', '>=u'}:
            return lhsn >= rhsn
        return False

    def _literal_eval_for_ce(self, lit, variable, value):
        parsed = self._parse_relation_literal(str(lit))
        if parsed is None:
            return None
        bits = self._mem_token_bits(variable)
        left = parsed['left']
        right = parsed['right']
        op = parsed['op']
        lkey = self._mem_token_key(left)
        rkey = self._mem_token_key(right)
        vkey = self._mem_token_key(variable)
        lbase = self._mem_token_base(left)
        rbase = self._mem_token_base(right)
        vbase = self._mem_token_base(variable)
        left_match = (
            (left == variable)
            or (lkey is not None and vkey is not None and lkey == vkey)
            or (lbase is not None and vbase is not None and lbase == vbase)
        )
        right_match = (
            (right == variable)
            or (rkey is not None and vkey is not None and rkey == vkey)
            or (rbase is not None and vbase is not None and rbase == vbase)
        )
        if left_match and self._is_const_token(right):
            cst = self._parse_int_token(right)
            if cst is None:
                return None
            lbits = self._mem_token_bits(left)
            if lbits is not None:
                bits = lbits
            return self._compare_rel(value, cst, op, bits)
        if right_match and self._is_const_token(left):
            cst = self._parse_int_token(left)
            iop = self._invert_relation(op)
            if cst is None or iop is None:
                return None
            rbits = self._mem_token_bits(right)
            if rbits is not None:
                bits = rbits
            return self._compare_rel(value, cst, iop, bits)
        return None

    def _candidate_accepts_ce_side(self, candidate, ce_data, field):
        variable = ce_data.get('variable')
        val = ce_data.get(field)
        if variable is None or val is None:
            return None
        seen = False
        for lit in candidate:
            lres = self._literal_eval_for_ce(lit, variable, int(val))
            if lres is None:
                continue
            seen = True
            if not lres:
                return False
        return True if seen else None

    def _ct_candidate_acceptable(self, candidate, e_insec=None):
        ce_pool = e_insec if isinstance(e_insec, list) else self.result_summary.get('ct_counterexamples', [])
        for ce_data in ce_pool:
            if not isinstance(ce_data, dict):
                continue
            # Ignore incomplete CE records; they are not informative for pruning.
            if ce_data.get('variable') is None:
                continue
            if ce_data.get('value_lo') is None and ce_data.get('value_hi') is None:
                continue
            lo = self._candidate_accepts_ce_side(candidate, ce_data, 'value_lo')
            hi = self._candidate_accepts_ce_side(candidate, ce_data, 'value_hi')
            if lo is None or hi is None:
                continue
            if lo is True and hi is True:
                return False, ce_data
        return True, None

    def _ct_memtok_to_varid(self, memtok):
        key = self._mem_token_key(memtok)
        if key is None:
            return None
        addr, nbytes = key
        return '0x{:08x}:{}'.format(addr, nbytes)

    def _ct_build_relation_term(self, variable, op, cst):
        if variable is None or op is None or cst is None:
            return None
        if not hasattr(self.checkers, 'context'):
            return None
        ctx = self.checkers.context
        varid = self._ct_memtok_to_varid(variable)
        if varid is None:
            return None
        try:
            vid = ctx.declare_var(varid)
            bits = self._mem_token_bits(variable)
            if bits is None or bits <= 0:
                bits = ctx.get_size(vid)
            if bits is None or bits <= 0:
                bits = 32
            digits = max(1, int((bits + 3) / 4))
            mask = (1 << bits) - 1 if bits < 4096 else (1 << 32) - 1
            cval = int(cst) & mask
            cid = ctx.declare_const('0x{:0{}x}'.format(cval, digits))
        except Exception:
            return None
        if op == '=':
            return ctx.create_binary_term(minibinsec.Operator.Equal, vid, cid)
        if op == '<>':
            return ctx.create_binary_term(minibinsec.Operator.Distinct, vid, cid)
        if op == '<s':
            return ctx.create_binary_term(minibinsec.Operator.Lower, vid, cid)
        if op == '<u':
            return ctx.create_binary_term(minibinsec.Operator.LowerU, vid, cid)
        if op == '>s':
            return ctx.create_binary_term(minibinsec.Operator.Lower, cid, vid)
        if op == '>u':
            return ctx.create_binary_term(minibinsec.Operator.LowerU, cid, vid)
        if op == '<=s':
            lt = ctx.create_binary_term(minibinsec.Operator.Lower, vid, cid)
            eq = ctx.create_binary_term(minibinsec.Operator.Equal, vid, cid)
            return ctx.create_multiterm(minibinsec.Operator.Or, [lt, eq])
        if op == '<=u':
            lt = ctx.create_binary_term(minibinsec.Operator.LowerU, vid, cid)
            eq = ctx.create_binary_term(minibinsec.Operator.Equal, vid, cid)
            return ctx.create_multiterm(minibinsec.Operator.Or, [lt, eq])
        if op == '>=s':
            gt = ctx.create_binary_term(minibinsec.Operator.Lower, cid, vid)
            eq = ctx.create_binary_term(minibinsec.Operator.Equal, vid, cid)
            return ctx.create_multiterm(minibinsec.Operator.Or, [gt, eq])
        if op == '>=u':
            gt = ctx.create_binary_term(minibinsec.Operator.LowerU, cid, vid)
            eq = ctx.create_binary_term(minibinsec.Operator.Equal, vid, cid)
            return ctx.create_multiterm(minibinsec.Operator.Or, [gt, eq])
        return None

    def _ct_literal_relation(self, lit):
        parsed = self._parse_relation_literal(str(lit))
        if parsed is None:
            return None
        left = parsed['left']
        right = parsed['right']
        op = parsed['op']
        if self._is_const_token(left) and self._mem_token_key(right) is not None:
            cst = self._parse_int_token(left)
            iop = self._invert_relation(op)
            if cst is None or iop is None:
                return None
            return {'variable': right, 'op': iop, 'const': cst}
        if self._mem_token_key(left) is not None and self._is_const_token(right):
            cst = self._parse_int_token(right)
            if cst is None:
                return None
            return {'variable': left, 'op': op, 'const': cst}
        return None

    def _ct_policy_secure(self, candidate):
        if not getattr(self.args, 'ct_mode', False):
            return False
        if hasattr(self.checkers, 'oracle_ct'):
            res = self.checkers.oracle_ct(set(candidate))
            return res.status == 'SECURE'
        gstatus, rstatus, _, _, _, _ = self.check_goals(set(candidate))
        return bool(gstatus and rstatus)

    def _ct_minimize_candidate(self, candidate):
        current = set(candidate)
        if len(current) <= 1:
            return current
        changed = True
        while changed and len(current) > 0:
            changed = False
            for lit in sorted(list(current), key=lambda x: (self._literal_complexity(x), str(x))):
                trial = set(current)
                trial.remove(lit)
                if self._ct_policy_secure(trial):
                    current = trial
                    changed = True
                    break
        return current

    def _ct_generalize_candidate_light(self, candidate):
        current = set(candidate)
        pivots = self._relevant_ct_pivots(current)
        if len(pivots) <= 0:
            return current

        total_tried = 0
        max_trials = 5
        seen = {self._ct_clause_key(current)}
        improved = True
        while improved and total_tried < max_trials:
            improved = False
            for pivot in pivots:
                if total_tried >= max_trials:
                    break
                pvar = self._canonical_ct_ce_variable(pivot.get('variable'))
                prec = str(pivot.get('relation', '')).strip()
                pcst = self._parse_int_token(pivot.get('constant'))
                if pvar is None or pcst is None:
                    continue

                side_unsigned = prec.endswith('u')
                lt = '<u' if side_unsigned else '<s'
                le = '<=u' if side_unsigned else '<=s'
                gt = '>u' if side_unsigned else '>s'
                ge = '>=u' if side_unsigned else '>=s'

                # Pivot-guided widening rules.
                if prec in {'>s', '>u'}:
                    proposal_specs = [(le, pcst), (lt, pcst + 1)]
                elif prec in {'>=s', '>=u'}:
                    proposal_specs = [(lt, pcst)]
                elif prec in {'<s', '<u'}:
                    proposal_specs = [(ge, pcst)]
                elif prec in {'<=s', '<=u'}:
                    proposal_specs = [(gt, pcst)]
                else:
                    proposal_specs = []
                if len(proposal_specs) <= 0:
                    continue

                relation_infos = self._candidate_relation_infos(current)
                pivot_applied = False
                for info in relation_infos:
                    ivar = info.get('variable')
                    lit = info.get('literal')
                    if ivar is None or lit is None:
                        continue
                    if not self._vars_match(ivar, pvar):
                        continue

                    for op, cval in proposal_specs:
                        if total_tried >= max_trials:
                            break
                        t = self._ct_build_relation_term(ivar, op, cval)
                        if t is None:
                            continue
                        trial = set(current)
                        trial.remove(lit)
                        trial.add(t)
                        tkey = self._ct_clause_key(trial)
                        if tkey in seen:
                            continue
                        seen.add(tkey)
                        total_tried += 1
                        if self._ct_policy_secure(trial):
                            current = trial
                            improved = True
                            pivot_applied = True
                            break
                    if pivot_applied or total_tried >= max_trials:
                        break
                if improved and total_tried < max_trials:
                    # Recompute relevant literals/pivots on the widened clause.
                    break
            if not improved:
                break
        return current

    def _ct_refine_secure_candidate(self, candidate):
        original = set(candidate)
        self._last_ct_refine_meta = {
            'minimized': False,
            'widened': False,
            'before_literals': self._stable_solution_literals(original),
            'after_minimize_literals': [],
            'after_widen_literals': [],
        }
        minimized = self._ct_minimize_candidate(original)
        self._last_ct_refine_meta['minimized'] = (set(minimized) != original)
        self._last_ct_refine_meta['after_minimize_literals'] = self._stable_solution_literals(minimized)
        generalized = self._ct_generalize_candidate_light(minimized)
        if generalized != minimized and self.check_necessity([generalized]):
            self._last_ct_refine_meta['widened'] = True
            self._last_ct_refine_meta['after_widen_literals'] = self._stable_solution_literals(generalized)
            return generalized
        self._last_ct_refine_meta['after_widen_literals'] = self._stable_solution_literals(minimized)
        return minimized

    def _finalize_ct_secure_baseline(self):
        true_policy = set()
        self._register_ct_secure_clause(true_policy, origin='baseline', minimized=False, widened=False)
        semantics = self._build_policy_semantics([true_policy])
        self.result_summary['q_safe'] = True
        self.result_summary['q_explain'] = []
        self.result_summary['q_explain_pivots'] = []
        self.result_summary['selected_policy'] = self._stable_solution_string(true_policy)
        self.result_summary['selected_policy_representative'] = self._stable_solution_string(true_policy)
        self.result_summary['selected_constraint'] = self._stable_solution_string(true_policy)
        self.result_summary['selected_constraint_representative'] = self._stable_solution_string(true_policy)
        self.result_summary['policy_condition'] = self._stable_solution_string(true_policy)
        self.result_summary['policy_condition_unified'] = self._stable_solution_string(true_policy)
        self.result_summary['policy_condition_compact'] = self._stable_solution_string(true_policy)
        self.result_summary['general_nas_condition'] = self._stable_solution_string(true_policy)
        self.result_summary['alternatives'] = []
        self.result_summary['nas_conditions_all'] = [self._stable_solution_string(true_policy)]
        self.result_summary['ct_validation'] = self._validate_ct_policy(true_policy)
        self.result_summary['policy_semantics'] = semantics
        self.result_summary['branch_guided_policies'] = self._derive_branch_guided_policies(semantics)
        self._sync_ct_dnf_summary()
        self.result_summary['selection_mode'] = 'ct-baseline'
        self.result_summary['selection_reason'] = {
            'mode': 'ct-baseline',
            'reason': 'oracle_ct(True) returned SECURE; selected q_safe=True',
            'branch_key': None,
        }
        self.stats.solution_clauses = 1
        self.stats.final_constraints = 1

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

    def _normalized_q_safe(self):
        qsafe = self.result_summary.get('q_safe')
        if qsafe is not None:
            return qsafe
        if getattr(self.args, 'ct_mode', False):
            selected = self.result_summary.get('selected_policy')
            if selected:
                return selected
        return qsafe

    def _q_leak_from_qsafe(self, qsafe):
        if qsafe is None:
            return None
        if isinstance(qsafe, bool):
            return not qsafe
        sval = str(qsafe).strip()
        if sval == '':
            return None
        return 'not({})'.format(sval)

    def _build_thesis_evidence(self):
        stats_data = self.result_summary.get('stats') or self._stats_to_dict()
        oracles = stats_data.get('oracles', {})
        timers = stats_data.get('timers', {})
        core = stats_data.get('core', {})

        total_oracle_calls = 0
        for data in oracles.values():
            try:
                total_oracle_calls += int(data.get('calls', 0))
            except Exception:
                continue

        by_source = {'oracle': 0, 'derived': 0}
        for ce in self.result_summary.get('ct_counterexamples', []):
            if not isinstance(ce, dict):
                continue
            src = str(ce.get('source', 'derived'))
            if src not in by_source:
                by_source[src] = 0
            by_source[src] += 1

        return {
            'queries': {
                'total_oracle_calls': total_oracle_calls,
                'binsec_calls': int(oracles.get('binsec', {}).get('calls', 0)),
                'minibinsec_calls': int(oracles.get('minibinsec', {}).get('calls', 0)),
            },
            'counterexamples': {
                'used': int(core.get('counterexamples', 0)),
                'ct_total': len(self.result_summary.get('ct_counterexamples', [])),
                'by_source': by_source,
            },
            'timing': {
                'timers': timers,
            },
        }

    def _build_recommendation(self, qsafe):
        if not getattr(self.args, 'ct_mode', False):
            return None
        baseline = str(self.result_summary.get('baseline_status') or '').upper()
        if baseline == 'SECURE':
            return 'Programa ya constant-time (q_safe = true). No se requiere precondicion.'
        if qsafe is None:
            return 'No se encontro precondicion util dentro del presupuesto. Recomendacion: rewrite CT (branchless + acceso memoria constante).'
        if isinstance(qsafe, bool):
            if qsafe:
                return 'Precondicion util encontrada: q_safe = true (seguridad global).'
            return 'q_safe = false; revisar modelo/oraculo.'

        s = str(qsafe)
        if ('<' in s) or ('>' in s) or ('|' in s):
            return 'Precondicion util encontrada para hacer el programa secure bajo esa restriccion.'
        if '=' in s and ('<' not in s) and ('>' not in s):
            return 'Precondicion encontrada pero estrecha/trivial. Considerar rewrite CT para seguridad mas robusta.'
        return 'Precondicion encontrada; validar utilidad practica del dominio permitido.'

    def _finalize_result_summary(self):
        # Ensure thesis-oriented fields are always available in report output.
        self.result_summary['baseline_status'] = self.result_summary.get('baseline_status')
        self.result_summary['leak_sites'] = self.result_summary.get('leak_sites', [])
        self.result_summary['q_explain'] = self.result_summary.get('q_explain', [])
        self.result_summary['ct_secure_clauses'] = self.result_summary.get('ct_secure_clauses', [])
        self.result_summary['ct_insecure_evidence'] = self.result_summary.get('ct_insecure_evidence', [])
        self.result_summary['ct_dnf_policy'] = self.result_summary.get('ct_dnf_policy')
        self.result_summary['ct_dnf_validation'] = self.result_summary.get('ct_dnf_validation')
        self.result_summary['ct_stop_reason'] = self.result_summary.get('ct_stop_reason')
        self.result_summary['ct_unknown_checks'] = int(self.result_summary.get('ct_unknown_checks', 0) or 0)
        self.result_summary['ct_saturation'] = self.result_summary.get('ct_saturation', {
            'attempts': 0,
            'saturated': False,
            'last_target': None,
        })
        self.result_summary['ct_clause_reductions'] = self.result_summary.get('ct_clause_reductions', {
            'checks': 0,
            'removed_clauses': 0,
            'deduplicated': 0,
        })

        if getattr(self.args, 'ct_mode', False):
            self._sync_ct_dnf_summary()
            # Keep explicit CT-DNF stop reasons (timeout|saturated|max_clauses).
            # Do not override with generic labels.

        qsafe = self._normalized_q_safe()
        self.result_summary['q_safe'] = qsafe
        self.result_summary['q_leak'] = self._q_leak_from_qsafe(qsafe)
        self.result_summary['evidence'] = self._build_thesis_evidence()
        self.result_summary['recommendation'] = self._build_recommendation(qsafe)

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
        display_expr = compact_expr if compact_expr is not None else unified_expr
        final_condition = compact_expr if compact_expr is not None else general_expr

        self.log.info('obtained a necessary result set')
        self.log.result('nas conditions (all): {}'.format(display_expr))
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
        self.result_summary['policy_condition_unified'] = display_expr
        self.result_summary['policy_condition_compact'] = compact_expr
        self.result_summary['general_nas_condition'] = general_expr
        self.result_summary['alternatives'] = [self._stable_solution_string(sol) for sol in alternatives]
        self.result_summary['nas_conditions_all'] = [self._stable_solution_string(sol) for sol in ordered]
        self.result_summary['ct_validation'] = self._validate_ct_policy(selected) if selected is not None else None
        self.result_summary['policy_semantics'] = semantics
        self.result_summary['branch_guided_policies'] = guided
        self.result_summary['selection_mode'] = selmeta['mode']
        self.result_summary['selection_reason'] = selmeta

    def _finalize_best_effort_result(self):
        # Fallback for hard benchmarks where NAS cannot be proven within the
        # allocated budget. Select a ranked sufficient policy without claiming
        # necessity.
        ordered, selmeta = self._ordered_unique_solutions([set(sol) for sol in self.engine.get_solutions()])
        self.engine.storage.solutions = ordered
        selected = ordered[0] if len(ordered) > 0 else None
        alternatives = ordered[1:] if len(ordered) > 1 else []
        general_expr = self._stable_policies_or_string(ordered)
        unified_expr = self._stable_unified_condition_string(ordered)
        compact_expr = self._compact_policy_condition(ordered)
        display_expr = compact_expr if compact_expr is not None else unified_expr
        final_condition = compact_expr if compact_expr is not None else general_expr

        self.log.warning('necessary set not found; selecting best-effort policy from sufficient clauses')
        self.log.result('sufficient conditions (all): {}'.format(display_expr))
        if selected is not None:
            self.log.result('selected best-effort constraint: {}'.format(final_condition))

        # Report a selected policy for downstream tooling, but keep semantic
        # distinction from NAS by recording a dedicated flag.
        self.stats.solution_clauses = len(ordered)
        self.stats.final_constraints = 1 if selected is not None else 0
        self.result_summary['selected_policy'] = final_condition if selected is not None else None
        self.result_summary['selected_policy_representative'] = self._stable_solution_string(selected) if selected is not None else None
        self.result_summary['selected_constraint'] = final_condition if selected is not None else None
        self.result_summary['selected_constraint_representative'] = self._stable_solution_string(selected) if selected is not None else None
        self.result_summary['policy_condition'] = general_expr
        self.result_summary['policy_condition_unified'] = display_expr
        self.result_summary['policy_condition_compact'] = compact_expr
        self.result_summary['general_nas_condition'] = None
        self.result_summary['alternatives'] = [self._stable_solution_string(sol) for sol in alternatives]
        self.result_summary['nas_conditions_all'] = []
        self.result_summary['ct_validation'] = self._validate_ct_policy(selected) if selected is not None else None
        self.result_summary['policy_semantics'] = self._build_policy_semantics(ordered)
        self.result_summary['branch_guided_policies'] = self._derive_branch_guided_policies(self.result_summary['policy_semantics'])
        self.result_summary['selection_mode'] = selmeta['mode']
        self.result_summary['selection_reason'] = selmeta
        self.result_summary['best_effort'] = True

    def solve(self):
        self.stats.start_timers(('solution', 'unsolution', 'counterex', 'example', 'necessaryc'))
        collect_until_timeout = getattr(self.args, 'collect_until_timeout', False)
        solver_timeout = getattr(self.args, 'solver_timeout', None)
        has_timeout = solver_timeout is not None and solver_timeout > 0
        max_solutions = getattr(self.args, 'max_solutions', None)
        start_time = time.time()
        nas_found = False

        if getattr(self.args, 'ct_mode', False) and hasattr(self.checkers, 'oracle_ct'):
            self.log.debug('running CT baseline diagnosis with oracle_ct(True)')
            baseline = self.checkers.oracle_ct(True)
            self.result_summary['baseline_status'] = baseline.status
            self.result_summary['leak_sites'] = self._format_leak_sites(baseline.leaks)
            if baseline.status == 'SECURE':
                self.log.info('ct baseline is SECURE; finishing with q_safe=True')
                if hasattr(self.checkers, 'ct_explain'):
                    self.checkers.ct_explain = []
                if hasattr(self.checkers, 'ct_explain_pivots'):
                    self.checkers.ct_explain_pivots = []
                self._finalize_ct_secure_baseline()
                self.result_summary['stats'] = self._stats_to_dict()
                self._finalize_result_summary()
                return self.result_summary
            if baseline.status == 'INSECURE':
                self.log.info('ct baseline is INSECURE; continuing abduction search')
                qex, piv = self._build_ct_explain(baseline.leaks)
                self.result_summary['q_explain'] = qex
                self.result_summary['q_explain_pivots'] = piv
                if hasattr(self.checkers, 'ct_explain'):
                    self.checkers.ct_explain = list(qex)
                if hasattr(self.checkers, 'ct_explain_pivots'):
                    self.checkers.ct_explain_pivots = list(piv)
            else:
                self.log.warning('ct baseline status is UNKNOWN; continuing abduction search')

            # Dedicated CT flow: collect secure clauses under DNF target
            # instead of stopping at the first necessary sufficient policy.
            self._solve_ct_dnf(start_time, has_timeout, solver_timeout, max_solutions)
            self.result_summary['stats'] = self._stats_to_dict()
            self._finalize_result_summary()
            return self.result_summary

        # Fast path: if the empty constraint already makes negative goals
        # unreachable while keeping a positive witness reachable, abduction is
        # unnecessary and the final policy is simply "true".
        self.log.debug('pre-checking empty candidate goals')
        gstatus0, rstatus0, _gmodel0, rmodel0, gcore0, _rcore0 = self.check_goals(set())
        if gstatus0 and rstatus0:
            self.log.result('satisfying solution: {}'.format(stringify(set())))
            self.store_solution(set(), gcore0)
            if rmodel0 is not None:
                self.engine.add_example(rmodel0)
            self.log.info('empty candidate already satisfies goals; skipping candidate search')
            self._finalize_nas_result()
            self.result_summary['stats'] = self._stats_to_dict()
            self._finalize_result_summary()
            return self.result_summary

        self.get_initital_examples()
        if self.args.const_detect:
            self.recover_necessary_constants()
        for candidate, core_candidate in self.next_candidate():
            if has_timeout and (time.time() - start_time) >= solver_timeout:
                self.log.warning('solver timeout reached ({}s), stopping search'.format(solver_timeout))
                if getattr(self.args, 'ct_mode', False):
                    self.result_summary['ct_stop_reason'] = 'timeout'
                break
            self.log.debug('trying candidate: {}'.format(candidate))
            self.log.debug('candidate is consistent')
            if getattr(self.args, 'ct_mode', False):
                acceptable, ce_data = self._ct_candidate_acceptable(candidate)
                if not acceptable:
                    self.stats.generation.pruned['ct_counterexample'] += 1
                    self.log.debug('candidate pruned by ct CE: pivot={} values=({}, {})'.format(
                        ce_data.get('pivot'),
                        ce_data.get('value_lo'),
                        ce_data.get('value_hi'),
                    ))
                    continue
            self.log.info('evaluating candidate: {}'.format(candidate))
            self.stats.generation.evaluated += 1
            gstatus, rstatus, gmodel, rmodel, gcore, rcore = self.check_goals(candidate)
            if gstatus and rstatus:
                solved_candidate = set(candidate)
                refine_meta = {'minimized': False, 'widened': False}
                if getattr(self.args, 'ct_mode', False):
                    refined = self._ct_refine_secure_candidate(solved_candidate)
                    if refined != solved_candidate:
                        self.log.debug('ct refine secure candidate: {} -> {}'.format(solved_candidate, refined))
                    solved_candidate = refined
                    refine_meta = dict(self._last_ct_refine_meta)
                self.log.result('satisfying solution: {}'.format(stringify(solved_candidate)))
                self.store_solution(solved_candidate, gcore if solved_candidate == set(candidate) else None)
                if getattr(self.args, 'ct_mode', False):
                    self._register_ct_secure_clause(
                        solved_candidate,
                        origin='search',
                        minimized=bool(refine_meta.get('minimized', False)),
                        widened=bool(refine_meta.get('widened', False)),
                        trace=refine_meta,
                    )
                self.engine.add_example(rmodel)
                if max_solutions is not None and max_solutions > 0 and self.stats.solutions >= max_solutions:
                    self.log.warning('max solutions reached ({}), stopping search'.format(max_solutions))
                    if getattr(self.args, 'ct_mode', False):
                        self.result_summary['ct_stop_reason'] = 'max_solutions'
                    break
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
                if getattr(self.args, 'ct_mode', False):
                    if self._is_useful_ct_model(gmodel):
                        self.log.info('counter-example (oracle): {}'.format(gmodel))
                        self.engine.add_counter_example(gmodel)
                        self._record_ct_counterexample('oracle', oracle_model=gmodel)
                    else:
                        dce = self._record_ct_counterexample('derived')
                        self.engine.add_counter_example({'*controlled': set()})
                        self.log.info(
                            'counter-example (derived): pivot={} values=({}, {})'.format(
                                dce.pivot, dce.value_lo, dce.value_hi
                            )
                        )
                else:
                    self.log.info('counter-example: {}'.format(gmodel))
                    self.engine.add_counter_example(gmodel)
                if len(core_candidate) == 1:
                    self.log.debug('check candidate necessity')
                    #TODO: Handle higher level necessary constraints
                    #TODO: WARNING: checkers.negate negates literal by literal, not literal combining operators!!!
                    nstatus, nmodel, ncore = self.check_vulnerability(self.checkers.negate(core_candidate), [])
                    if not nstatus:
                        self.log.result('necessary constraint: {}'.format(stringify(core_candidate)))
                        added = self.engine.add_necessary_lit(core_candidate)
                        if added:
                            self.engine.restart_local_generation()
                        else:
                            self.log.debug('necessary constraint already known; skip restart')
                elif self.args.force_on_model_resorting:
                    self.engine.add_example(nmodel)
                    # TODO: Restart is not required here, only resorting, but no primitive exist
                    self.engine.restart_local_generation()
            else:
                self.log.debug('unsatisfying example with no counter-example')
        if nas_found and self.result_summary.get('selected_policy') is None:
            self._finalize_nas_result()
        elif (not nas_found
              and getattr(self.args, 'best_effort_policy', False)
              and len(self.engine.get_solutions()) > 0):
            self._finalize_best_effort_result()
        elif getattr(self.args, 'ct_mode', False) and self.result_summary.get('selected_policy') is None:
            qex = self.result_summary.get('q_explain') or []
            if qex:
                self.log.warning('no secure policy found within budget; returning q_explain guidance')
                self.log.result('q_explain (fallback): {}'.format(qex))
            if self.result_summary.get('ct_stop_reason') is None:
                self.result_summary['ct_stop_reason'] = 'no_policy_found'
        self.result_summary['stats'] = self._stats_to_dict()
        self._finalize_result_summary()
        return self.result_summary
# --------------------
