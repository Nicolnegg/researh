# ----------------------------------------
import sys
from subprocess import Popen, STDOUT, PIPE, TimeoutExpired
# ----------------------------------------
def execute_command(cmd, timeout=None, stdin=None, merge_output=True):
    """Executes the system command `cmd` (list of parameters, typed for `Popen`).

    Stops the execution after `timeout` seconds (never if `timeout` is `None`).
    If `stdin` is not `None`, the string is forwarded to the standard input of the execution.

    Returns a tuple `rc`, `to`, `out`, `err` with `rc` the return code of the execution,
    `to` a boolean value set to `True` iff timeout was exceeded,
    `out` the decoded standard output of the command and `err` the decoded standard error.
    If `merge_output` is `True`, `out` contains both the standard input and standard error and `err` is `None`.
    """
    if stdin is not None:
        stdin = stdin.encode('utf-8')
    proc = Popen(cmd, stdout=PIPE, stderr=(STDOUT if merge_output else PIPE), stdin=(PIPE if stdin is not None else None))
    to_status = False
    try:
        cout, cerr = proc.communicate(timeout=timeout, input=stdin)
    except TimeoutExpired:
        to_status = True
        proc.kill()
        cout, cerr = proc.communicate()
    return proc.returncode, to_status, cout.decode(sys.stdout.encoding, errors='ignore'), cerr.decode(sys.stderr.encoding, errors='ignore') if cerr is not None else None
# ----------------------------------------
