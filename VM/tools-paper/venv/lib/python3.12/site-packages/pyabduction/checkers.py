# -------------------$
# --------------------
# --------------------
class CheckerResult:

    def __init__(self, status, model, core):
        self.status = status
        self.model = model
        self.core = core

    def __iter__(self):
        yield self.status
        yield self.model
        yield self.core
# --------------------
ConsequenceCheckModes = [
    'fast',
    'exact',
]
# --------------------
class AbstractChecker:

    def __init__(self, args, stats, logger):
        self.args = args
        self.stats = stats
        self.log = logger

    def check_consistency(self, candidate):
        raise NotImplementedError(self)

    def check_necessity(self, solutions):
        raise NotImplementedError(self)

    def check_vulnerability(self, candidate, reject, complete=False):
        raise NotImplementedError(self)

    def check_goals(self, candidate):
        raise NotImplementedError(self)

    def check_consequence(self, implicant, implicate, mode_override=None):
        raise NotImplementedError(self)

    def check_satisfied(self, candidate, model):
        raise NotImplementedError(self)
# --------------------
