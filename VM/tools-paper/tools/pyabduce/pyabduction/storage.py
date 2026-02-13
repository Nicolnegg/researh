# -------------------$
# --------------------
# --------------------
# --------------------
class StorageTable:

    def __init__(self, args, checkers, logger, mode=None):
        self.args = args
        self.checkers = checkers
        self.mode = mode if mode is not None else self.args.consequence_checks_mode
        self.solutions = []
        self.log = logger

    def store(self, solution):
        # Fast syntactic antichain pruning:
        # keep only subset-minimal conjunctions (drop supersets/redundant joins).
        solution_set = set(solution)
        kept = []
        for existing in self.solutions:
            existing_set = set(existing)
            if existing_set.issubset(solution_set):
                return
            if solution_set.issubset(existing_set):
                continue
            kept.append(existing)
        self.solutions = kept

        self.solutions = [ s for s in self.solutions if not self.checkers.check_consequence(s, solution, mode_override=self.mode)[0] ]
        if len([ s for s in self.solutions if self.checkers.check_consequence(solution, s, mode_override=self.mode)[0] ]) == 0:
            self.solutions.append(solution)

    def __iter__(self):
        return self.solutions.__iter__()
# --------------------
