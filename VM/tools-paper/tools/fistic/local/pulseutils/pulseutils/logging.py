# -------------------$
import sys
import re
import enum
import time
import curses
from colorama import Fore, Style
from tqdm import tqdm
# --------------------
class DummyProgressBar:
    def __init__(self, total=None):
        pass
    def update(self, i):
        pass
    def close(self):
        pass
# --------------------
class Logger:

    def __init__(self, out=sys.stdout, err=sys.stderr, level=4, debug_cover=5, color=False, log_progress=True):
        self.out = out
        self.err = err
        self.level = level
        self.debug_cover = debug_cover
        self.color = color
        self.log_progress = log_progress
        self._on_capture = False
        self._captured_msg = []
        self._set_loggers()

    def set_level(self, level):
        self.level = level
        self._set_loggers()

    def set_debug_cover(self, level):
        self.debug_cover = level
        self._set_loggers()

    def set_progress(self, progress):
        self.log_progress = log_progress
        self._set_loggers()

    def set_color(self, color):
        self.color = color
        self._set_loggers()

    def no_output(self):
        pass

    def output(self, log, ltxt='[       ]', color_a='', color_b=''):
        self.err.write('{}{}:{}{} {}{}\n'.format(color_a, ltxt, Style.RESET_ALL if self.color else '', color_b, log, Style.RESET_ALL if self.color else ''))

    def output_start(self, log, ltxt='[       ]', color_a='', color_b=''):
        self.err.write('{}{}:{}{} {}{} : '.format(color_a, ltxt, Style.RESET_ALL if self.color else '', color_b, log, Style.RESET_ALL if self.color else ''))
        self.err.flush()

    def output_end(self, b, log_t='done', log_f='failed', color_t='', color_f=''):
        self.err.write('{}{}{}\n'.format(color_t if b else color_f, log_t if b else log_f, Style.RESET_ALL if self.color else ''))

    def capture(self):
        self._on_capture = True
        setattr(self, 'debug',     lambda log : self._captured_msg.append(('debug', log)))
        setattr(self, 'info',      lambda log : self._captured_msg.append(('info', log)))
        setattr(self, 'warning',   lambda log : self._captured_msg.append(('warning', log)))
        setattr(self, 'error',     lambda log : self._captured_msg.append(('error', log)))
        setattr(self, 'critical',  lambda log : self._captured_msg.append(('critical', log)))
        setattr(self, 'fatal',     lambda log : self._captured_msg.append(('fatal', log)))
        setattr(self, 'result',    lambda log : self._captured_msg.append(('result', log)))
        setattr(self, 'check',     lambda log : self._captured_msg.append(('check', log)))
        setattr(self, 'check_end', lambda log : self._captured_msg.append(('check_end', log)))

    def uncapture(self):
        self._on_capture = False
        self._set_loggers()
        while self._captured_msg:
            lvl, msg = self._captured_msg.pop(0)
            getattr(self, lvl)(msg)

    def _set_loggers(self):
        if self._on_capture:
            return
        if self.log_progress:
            setattr(self, 'progress', lambda i : tqdm(i))
            setattr(self, 'progress_bar', lambda total : tqdm(total=total))
        else:
            setattr(self, 'progress', lambda i : i)
            setattr(self, 'progress_bar', lambda total : DummyProgressBar())
        if self.color:
            setattr(self, 'debug',       lambda log : self.output(log, ltxt='[debug]  ', color_a=Style.DIM, color_b=Style.DIM))
            setattr(self, 'info',        lambda log : self.output(log, ltxt='[info]   ', color_a=Fore.CYAN, color_b=''))
            setattr(self, 'warning',     lambda log : self.output(log, ltxt='[warning]', color_a=Fore.YELLOW + Style.BRIGHT, color_b=Fore.YELLOW))
            setattr(self, 'error',       lambda log : self.output(log, ltxt='[error]  ', color_a=Fore.RED + Style.BRIGHT, color_b=Fore.RED))
            setattr(self, 'critical',    lambda log : self.output(log, ltxt='[fatal]  ', color_a=Fore.MAGENTA + Style.BRIGHT, color_b=Fore.MAGENTA))
            setattr(self, 'fatal',       lambda log : self.output(log, ltxt='[fatal]  ', color_a=Fore.MAGENTA + Style.BRIGHT, color_b=Fore.MAGENTA))
            setattr(self, 'result',      lambda log : self.output(log, ltxt='[result] ', color_a=Fore.GREEN, color_b=''))
            setattr(self, 'check', lambda log : self.output_start(log, ltxt='[info]   ', color_a=Fore.CYAN, color_b=''))
            setattr(self, 'check_end', lambda b, m='done' : self.output_end(b, log_t=m, color_t=Fore.GREEN, color_f=Fore.RED))
        else:
            setattr(self, 'debug',       lambda log : self.output(log, ltxt='[debug]  '))
            setattr(self, 'info',        lambda log : self.output(log, ltxt='[info]   '))
            setattr(self, 'warning',     lambda log : self.output(log, ltxt='[warning]'))
            setattr(self, 'error',       lambda log : self.output(log, ltxt='[error]  '))
            setattr(self, 'critical',    lambda log : self.output(log, ltxt='[fatal]  '))
            setattr(self, 'fatal',       lambda log : self.output(log, ltxt='[fatal]  '))
            setattr(self, 'result',      lambda log : self.output(log, ltxt='[result] '))
            setattr(self, 'check', lambda log : self.output_start(log, ltxt='[info]   '))
            setattr(self, 'check_end', lambda b, m='done' : self.output_end(b, log_t=m))
        for tlvl, lvl in (('debug', 4), ('info', 3), ('warning', 2), ('error', 1), ('critical', 0), ('fatal', 0), ('check', 3), ('check_end', 3), ('result', 0)):
            if self.debug_cover <= lvl:
                setattr(self, tlvl, lambda log : self.no_output())
            if self.level < lvl:
                setattr(self, tlvl, lambda log : self.no_output())
# --------------------
class TaskStatus(enum.Enum):
    Pending = 'pending'
    Running = 'running'
    Completed = 'completed'
# --------------------
class Layout:

    def __init__(self, maxl, maxc, linit=0, cinit=0, lstep=1, cstep=1):
        self.maxl = maxl
        self.maxc = maxc
        self.lstep = lstep
        self.cstep = cstep
        self.l = linit
        self.c = cinit
        self.mapping = {}
        self.states = {}
        self.freecells = []
        self.drawnfcells = set()

    def next(self):
        res = self.l, self.c
        self.c += self.cstep
        if self.c >= self.maxc:
            self.c = 0
            self.l += self.lstep
            if self.l >= self.maxl:
                raise ValueError(self.l)
        return res

    def get(self, tid):
        if not tid in self.mapping:
            self.mapping[tid] = self.freecells.pop(0)[0] if self.freecells else self.next()
            self.drawnfcells.discard(self.mapping[tid])
        return self.mapping[tid]

    def get_state(self, tid):
        if not tid in self.states:
            self.states[tid] = None
        return self.states[tid]

    def set_state(self, tid, data):
        self.states[tid] = data

    def clear(self, tid):
        if tid in self.mapping:
            freeloc = self.mapping.pop(tid)
            self.freecells.append((freeloc, tid))
        if tid in self.states:
            self.states.pop(tid)
# --------------------
class ParallelStatusesLogger:

    CSPLITS = 6

    def __init__(self, tasks, title, keys):
        self.title = title
        self.keys = keys
        self.tasks = tasks
        self.layout = None
        self.cstate = (None, None, None)
        self.rinitd = False

    def _init_curses_data(self):
        curses.init_pair(11, curses.COLOR_BLACK, curses.COLOR_GREEN)

    def start(self):
        curses.wrapper(self._run)

    def _run(self, stdscr):
        self._init_curses_data()
        self.layout = Layout(curses.LINES, self.CSPLITS, linit=8, lstep=3)
        completed = False
        while not completed:
            c_completed = 0
            c_running = 0
            c_pending = 0
            r_statuses = {}
            for task in self.tasks:
                status, key = task.get_state()
                if status == TaskStatus.Completed:
                    self.layout.clear(task.get_id())
                    c_completed += 1
                if status == TaskStatus.Pending:
                    c_pending += 1
                if status == TaskStatus.Running:
                    c_running += 1
                    r_statuses[task.get_id()] = key
            self._refresh(stdscr, r_statuses, c_pending, c_running, c_completed)
            completed = c_completed == len(self.tasks)
            time.sleep(0.2)

    def _refresh(self, stdscr, rstatus, pending, running, completed):
        updated = False
        if not self.rinitd:
            stdscr.clear()
            self._draw_title(stdscr)
            self.rinitd = True
            updated = True
        updated = updated or self._refresh_running(stdscr, rstatus)
        updated = updated or self._refresh_freed(stdscr)
        if self.cstate != (pending, running, completed):
            self.cstate = (pending, running, completed)
            self._draw_non_running(stdscr, pending, running, completed)
            updated = True
        if updated:
            stdscr.refresh()

    def _draw_title(self, stdscr):
        xtitle = int(curses.COLS / 2 - len(self.title) / 2)
        stdscr.addstr(1, xtitle, self.title)

    def _draw_non_running(self, stdscr, pending, running, completed):
        stdscr.addstr(1, 1, '┌─────────Tasks─────────┐')
        stdscr.addstr(2, 1, '│ Pending:   {:10d} ├'.format(pending))
        stdscr.addstr(3, 1, '│ Running:   {:10d} │'.format(running))
        stdscr.addstr(4, 1, '│ Completed: {:10d} │'.format(completed))
        stdscr.addstr(5, 1, '└───────────────────────┴')

        top, genbar, bot, nshow = self._progressbar(completed, len(self.tasks), curses.COLS - 24)
        stdscr.addstr(2, 26, top[1:])
        stdscr.addstr(3, 26, genbar[1:])
        stdscr.addstr(3, 26, '█'*nshow)
        stdscr.addstr(4, 26, genbar[1:])
        stdscr.addstr(4, 26, '█'*nshow)
        stdscr.addstr(5, 26, bot[1:])

    def _refresh_running(self, stdscr, rstatus):
        updated = False
        for task, istatename in rstatus.items():
            try:
                if self.layout.get_state(task) != istatename:
                    self._refresh_rtask(stdscr, task, istatename, self.layout.get(task), self.CSPLITS)
                    self.layout.set_state(task, istatename)
                    updated = True
            except ValueError:
                # Not enough screen space to draw all parallel tasks
                pass
        return updated

    def _resized_text(self, text, size, pad):
        nsize = max(size - pad, 3)
        if len(text) <= nsize:
            return text
        cuts = len(text) - nsize - 1
        lcut = int((len(text) - cuts)/2)
        ntext = text[:lcut] + '…' + text[-lcut:]
        return ntext

    def _refresh_rtask(self, stdscr, task, istatename, loc, splits):
        line, col = loc
        if line + 2 >= curses.LINES:
            return # Not enough space to draw task
        istate = self.keys.index(istatename) if istatename != 'complete' else len(self.keys)
        COLS = (curses.COLS - 2)
        cpadding = int(COLS / splits)
        ccenter = int(1 + (col * COLS / splits) + (COLS / splits) / 2)
        taskname = self._resized_text(task, cpadding, 6)
        xtaskname = int(ccenter - len(taskname) / 2)
        xstatename = int(ccenter - len(istatename) / 2)
        top, localstate, bot, nshow = self._progressbar(istate, len(self.keys), cpadding)
        centerline = '{0: ^{1}s}'.format(self._resized_text(istatename, cpadding, 6), len(top) - 2)
        xtaskstate = int(ccenter - len(localstate) / 2)
        stdscr.addstr(line, xtaskstate, top)
        stdscr.addstr(line, xtaskname, taskname)
        stdscr.addstr(line + 1, xtaskstate, localstate)
        stdscr.addstr(line + 2, xtaskstate, bot)
        for xcurr in range(len(centerline)):
            if xcurr < nshow:
                #stdscr.addstr(line + 1, xtaskstate + 1 + xcurr, centerline[xcurr], curses.color_pair(11))
                stdscr.addstr(line + 1, xtaskstate + 1 + xcurr, centerline[xcurr], curses.A_REVERSE)
            else:
                stdscr.addstr(line + 1, xtaskstate + 1 + xcurr, centerline[xcurr])

    def _refresh_freed(self, stdscr):
        updated = False
        for loc, task in self.layout.freecells:
            if not loc in self.layout.drawnfcells:
                self._refresh_rtask(stdscr, task, 'complete', loc, self.CSPLITS)
                updated = True
        return updated

    def _progressbar(self, curr, total, size):
        nsize = max(size - 4, 1)
        nshow = min(int(curr*nsize/total), nsize)
        nhide = max(nsize - nshow, 0)
        top = '┌{}┐'.format('─'*nsize)
        nbar = '│{}│'.format(' '*nsize)
        bot = '└{}┘'.format('─'*nsize)
        return top, nbar, bot, nshow
# --------------------
