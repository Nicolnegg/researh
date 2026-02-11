# -------------------$
# --------------------
# --------------------
# --------------------
class ModelTable:

    def __init__(self, args, checkers, logger):
        self.args = args
        self.checkers = checkers
        self.models = []
        self.log = logger

    def add(self, model):
        self.models.append(model)

    def get_any(self):
        return self.models[0]

    def __iter__(self):
        return self.models.__iter__()
# --------------------
