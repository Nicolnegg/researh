# --------------------
import sys
import cmd
import traceback
# from .docker import DockerRunner, NoDockerRunner
from .engine import ContextLoader, SeaticRunner, seatic_action
# --------------------
class SeaticShell(cmd.Cmd, SeaticRunner):

    def __init__(self, args):
        cmd.Cmd.__init__(self)
        SeaticRunner.__init__(self, args, actions=[])
        self.prompt = '[seatic] > '
        self.opts = {
        }

    def run(self):
        self.cmdloop()
        super().run()

    def preloop(self):
        self.log.debug('initializing seatic shell')

    def postloop(self):
        self.log.debug('exiting seatic shell')

    def onecmd(self, line):
        try:
            return super().onecmd(line)
        except Exception as e:
            traceback.print_exc()

    def do_EOF(self, arg):
        sys.stdout.write('\n')
        return True

    def do_exit(self, arg):
        return True

    def do_set(self, arg):
        'set local arg variable to value'
        arg_data = arg.split(' ')
        dest = arg_data[0]
        val = ' '.join(arg_data[1:])
        if dest == 'ctx':
            return self.do_setctx(val)
        if dest in self.opts:
            self.log.warning('overriding opt var {}'.format(dest))
        self.opts[dest] = val

    def do_setctx(self, arg):
        'set context variable to value'
        args = arg.split()
        ctxid = args[0]
        val = ' '.join(args[1:])
        self.ctx[ctxid] = eval(val)

    def do_show(self, arg):
        'show value of variable'
        arg_data = arg.split(' ')
        dest = arg_data[0]
        val = ' '.join(arg_data[1:])
        if dest == 'ctx':
            return self.do_showctx(val)
        self.log.result('{}: {}'.format(dest, self.opts[dest]))

    def do_showctx(self, arg):
        'show value of context variable'
        self.log.result('{}: {}'.format(arg, self.ctx[arg]))

    def do_dockerize(self, arg):
        raise NotImplementedError()
        # del self.denv
        # TODO: Warning: consecutive context dockerization will fail
        # self.denv = DockerRunner(  ) # TODO: load keyfile, etc. from self.opts as namespace + self.args as fallback
        # self.denv.dockerize_context(self.ctx)

    def do_loadctx(self, arg):
        'load context from file'
        self.ctx = ContextLoader(self.log, arg, self.ctx).ctx
        self.tm.ctx = self.ctx

    def do_add(self, arg):
        task = seatic_action(arg)
        if task is not None:
            self.tm.generate_tasks(task)
        else:
            raise ValueError('unknown seatic action: {}'.format(arg))

    def do_run(self, arg):
        if arg:
            self.do_add(arg)
        self.tm.run()
        self.tm.flush_tasklist()
# --------------------
