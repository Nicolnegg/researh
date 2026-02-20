import unittest
from types import SimpleNamespace

from pyabduction.solver import AbductionSolver


class DummyLogger:
    def debug(self, *_args, **_kwargs):
        return None

    def info(self, *_args, **_kwargs):
        return None

    def warning(self, *_args, **_kwargs):
        return None

    def result(self, *_args, **_kwargs):
        return None


class Lit:
    def __init__(self, text, complexity=1):
        self.text = text
        self._complexity = complexity

    def __str__(self):
        return self.text

    def __hash__(self):
        return hash(self.text)

    def __eq__(self, other):
        return isinstance(other, Lit) and self.text == other.text

    def complexity(self):
        return self._complexity


class FakeContext:
    def __init__(self):
        self._sizes = {}

    def declare_var(self, token):
        # token style: "0xADDR:4"
        if ':' in token:
            _, nbytes = token.split(':', 1)
            self._sizes[token] = int(nbytes) * 8
        else:
            self._sizes[token] = 32
        return token

    def declare_const(self, token):
        nhex = len(token.replace('0x', ''))
        self._sizes[token] = 4 * nhex
        return token

    def get_size(self, token):
        return self._sizes[token]

    def _render(self, token):
        if token.startswith('0x') and ':' in token:
            addr, nbytes = token.split(':', 1)
            return '@[{},{}]'.format(addr, nbytes)
        return token

    def create_binary_term(self, op, id1, id2):
        return Lit('({} {} {})'.format(self._render(id1), str(op), self._render(id2)))

    def create_multiterm(self, op, terms):
        ordered = sorted(str(t) for t in terms)
        return Lit((' {} '.format(str(op))).join(ordered), complexity=2)


class FakeCheckers:
    def __init__(self):
        self.context = FakeContext()

    def check_consistency(self, _candidate):
        return True, None, None

    def check_necessity(self, _solutions):
        return True

    def evaluate_ct_policy(self, candidate):
        if len(candidate) == 0:
            return {'status': 'insecure', 'leaks': [{'raw': 'leak'}]}
        return {'status': 'secure', 'leaks': []}


class FakeEngine:
    def __init__(self, solutions):
        self._solutions = solutions
        self.storage = SimpleNamespace(solutions=list(solutions))

    def get_solutions(self):
        return list(self._solutions)

    def get_stringified_solutions(self):
        return ['{' + ', '.join(sorted(str(l) for l in sol)) + '}' for sol in self._solutions]


def make_solver(selection_mode='branch-first'):
    args = SimpleNamespace(
        ct_mode=True,
        selection_mode=selection_mode,
        solver_timeout=None,
        collect_until_timeout=False,
        const_detect=False,
        vexamples_init_count=0,
    )
    return AbductionSolver(
        args=args,
        engine=FakeEngine([]),
        checkers=FakeCheckers(),
        stats=SimpleNamespace(),
        logger=DummyLogger(),
    )


class TestCTRegression(unittest.TestCase):
    def test_branch_first_prefers_branch_policies(self):
        solver = make_solver(selection_mode='branch-first')
        solutions = [
            {Lit('(@[0x080e3f48,4] = @[0x080e3f4c,4])')},  # collateral
            {Lit('(0x00000007 <s @[0x080e3f4c,4])')},      # branch true
            {Lit('(@[0x080e3f4c,4] = 0x00000007)')},       # branch equal
        ]
        ordered, meta = solver._ordered_unique_solutions(solutions)
        self.assertEqual(meta['mode'], 'branch-first')
        self.assertIn('@[0x080e3f4c,4]', str(next(iter(ordered[0]))))
        self.assertNotIn('@[0x080e3f48,4] = @[0x080e3f4c,4]', str(next(iter(ordered[0]))))

    def test_branch_first_falls_back_without_two_supporting_solutions(self):
        solver = make_solver(selection_mode='branch-first')
        solutions = [
            {Lit('(@[0x080e3f48,4] = @[0x080e3f4c,4])')},  # collateral
            {Lit('(0x00000007 <s @[0x080e3f4c,4])')},      # only one branch policy for pivot
        ]
        _ordered, meta = solver._ordered_unique_solutions(solutions)
        self.assertEqual(meta['mode'], 'size-complexity')
        self.assertIn('fallback', meta['reason'])

    def test_size_complexity_mode_is_selectable(self):
        solver = make_solver(selection_mode='size-complexity')
        solutions = [
            {Lit('(0x00000007 <s @[0x080e3f4c,4])')},
            {Lit('(@[0x080e3f4c,4] = 0x00000007)'), Lit('(@[0x080e3f48,4] = @[0x080e3f4c,4])')},
        ]
        ordered, meta = solver._ordered_unique_solutions(solutions)
        self.assertEqual(meta['mode'], 'size-complexity')
        self.assertEqual(len(ordered[0]), 1)

    def test_finalize_summary_contains_branch_guided_and_stable_keys(self):
        solutions = [
            {Lit('(0x00000007 <s @[0x080e3f4c,4])')},
            {Lit('(@[0x080e3f4c,4] <s 0x00000007)')},
            {Lit('(@[0x080e3f4c,4] = 0x00000007)')},
            {Lit('(@[0x080e3f48,4] = @[0x080e3f4c,4])')},
        ]
        solver = make_solver(selection_mode='branch-first')
        solver.engine = FakeEngine(solutions)
        solver._semantic_post_filter_solutions = lambda sols: sols
        solver._finalize_nas_result()
        summary = solver.result_summary

        self.assertIn('selected_policy', summary)
        self.assertIn('alternatives', summary)
        self.assertIn('nas_conditions_all', summary)
        self.assertIn('policy_semantics', summary)
        self.assertIn('branch_guided_policies', summary)
        self.assertIn('selection_mode', summary)
        self.assertIn('selection_reason', summary)
        self.assertEqual(summary['selection_mode'], 'branch-first')
        self.assertTrue(len(summary['branch_guided_policies']) >= 1)
        self.assertTrue(summary['branch_guided_policies'][0]['recommended_split'])


if __name__ == '__main__':
    unittest.main()
