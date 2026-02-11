# ----------------------------------------
import enum
# ----------------------------------------
class TaskStatus(enum.Enum):
    Pending     = -2
    Running     = -1
    Complete    = 0
    Failure     = 1
    HardFailure = 2
# ----------------------------------------
class TaskException(Exception):

    def __init__(self, reason, log):
        super().__init__(self, reason)
        self.log = log
# ----------------------------------------
# ----------------------------------------
