# ----------------------------------------
import sys
from colorama import Fore, Style
# ----------------------------------------
def clog_reasons(stream, rstr, col=True):
    def rcol(rstr):
        if 'ok' in rstr:
            return Fore.GREEN
        elif 'nzr' in rstr:
            return Fore.RED
        return Fore.YELLOW
    lcol0 = rcol(rstr) if col else ''
    lcol1 = Style.RESET_ALL if col else ''
    stream.write(lcol0)
    stream.write(rstr)
    stream.write(lcol1)
    stream.write('\n')
# ----------------------------------------
def clog_stack(stream, stack, col=True):
    lcol0 = Fore.RED if col else ''
    lcol1 = Fore.YELLOW if col else ''
    lcol2 = Style.RESET_ALL if col else ''
    for line in stack:
        rline = str(line)
        if '\n' in rline:
            stream.write(lcol1)
        else:
            stream.write(lcol0)
        stream.write(rline)
        stream.write('\n')
    stream.write(lcol2)
    stream.write('\n')
# ----------------------------------------
