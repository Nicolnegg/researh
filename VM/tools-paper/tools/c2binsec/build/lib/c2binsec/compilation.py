# ----------------------------------------
import sys
import os
from .core import TaskStatus, TaskException
from pulseutils.system import execute_command
from .cupdate import generate_update
from pulseutils.assembly import x86AsmData
# ----------------------------------------
# ----------------------------------------
class CompilationFiles:

    def __init__(self, filename, superdir=None):
        self.input = filename
        self.outdir = '{}.dir'.format(os.path.splitext(filename)[0])
        if superdir is not None:
            self.outdir = os.path.join(superdir, self.outdir)
        os.makedirs(self.outdir, exist_ok=True)
        corename = os.path.basename(os.path.splitext(filename)[0])
        self.output       = os.path.join(self.outdir, '{}.uc.raw.c'.format(corename))
        self.intermediate = os.path.join(self.outdir, '{}.temp.raw.c'.format(corename))
        self.binary       = os.path.join(self.outdir, '{}.bin'.format(corename))
        self.dump         = os.path.join(self.outdir, '{}.bin.s'.format(corename))
        self.dumptbl      = os.path.join(self.outdir, '{}.bin.s2'.format(corename))
        self.stub         = os.path.join(self.outdir, '{}.stub.raw.c'.format(corename))
        self.bconfig      = os.path.join(self.outdir, '{}.binsec.config'.format(corename))
        self.bmemory      = os.path.join(self.outdir, '{}.binsec.memory'.format(corename))
        self.rconfig      = os.path.join(self.outdir, '{}.robust.config'.format(corename))
        self.rmemory      = os.path.join(self.outdir, '{}.robust.memory'.format(corename))
        self.runner       = os.path.join(self.outdir, '{}.run.bash'.format(corename))
        self.rrunner      = os.path.join(self.outdir, '{}.robust-run.bash'.format(corename))
        self.adirectives  = os.path.join(self.outdir, '{}.abd.directives.txt'.format(corename))
        self.aliterals    = os.path.join(self.outdir, '{}.abd.literals.txt'.format(corename))
        self.arunner      = os.path.join(self.outdir, '{}.abduce-run.bash'.format(corename))
# ----------------------------------------
class CompilationTask:

    def __init__(self, ifile, args, ruleset):
        self.files = CompilationFiles(ifile, args.output_dir)
        self.args = args
        self.ruleset = ruleset
        self.debug_stack = []
        self.forward = None
        self.context = {}
        self.status = TaskStatus.Pending

    def __call__(self):
        try:
            self.status = TaskStatus.Running
            self.debug_stack.append('compiling {} -> {}'.format(self.files.input, self.files.runner))
            if not (self.args.skip_existing and os.path.isfile(self.files.runner)):
                self._build_intermediate()
                self._generate_code()
                self._compile_code()
                self._disasm_code()
                self._build_config()
                self._build_runner()
            self.status = TaskStatus.Complete
        except TaskException as e:
            self.status = TaskStatus.Failure
            self.debug_stack.append(e.log)
            self.debug_stack.append(e)
        except Exception as e:
            self.status = TaskStatus.HardFailure
            self.debug_stack.append(e)

    def _build_intermediate(self):
        with open(self.files.input) as istr:
            data = istr.read()
        with open(self.files.intermediate, 'w') as ostr:
            self.forward = self.ruleset.write_cpp_compliant(ostr, data, stack=self.debug_stack)

    def _generate_code(self):
        ast, data = generate_update(self.files.intermediate, self.ruleset.crules, stack=self.debug_stack)
        self.context['symbols'] = data.symbols
        prepatch = self.ruleset.build_c_prepatch(self.forward)
        with open(self.files.output, 'w') as ostr:
            self.ruleset.write_c_update(ostr, ast, data, prepatch=prepatch, stack=self.debug_stack)
        with open(self.files.stub, 'w') as ostr:
            self.ruleset.write_c_stubs(ostr, data, stack=self.debug_stack)

    def _compile_code(self):
        command = self.ruleset.make_compilation_command((self.files.stub, self.files.output), self.files.binary)
        self.debug_stack.append('run {}'.format(' '.join(command)))
        ret, to, out, err = execute_command(command)
        if ret != 0:
            raise TaskException('compilation failed', out)

    def _disasm_code(self):
        command = self.ruleset.make_disasm_command(self.files.binary)
        self.debug_stack.append('run {}'.format(' '.join(command)))
        ret, to, out, err = execute_command(command, merge_output=False)
        with open(self.files.dump, 'w') as ostr:
            ostr.write(out)
        if ret != 0 or err.strip():
            self._disasm_symtable(perr=err)
        else:
            self._disasm_symtable(perr='ok')

    def _disasm_symtable(self, perr=''):
        self.debug_stack.append('trying symbol table supplementation')
        command = self.ruleset.make_disasm_table_command(self.files.binary)
        self.debug_stack.append('run {}'.format(' '.join(command)))
        ret, to, out, err = execute_command(command, merge_output=False)
        with open(self.files.dumptbl, 'w') as ostr:
            ostr.write(out)
        if ret != 0:
            raise TaskException('all disasm commands failed', perr+err)

    def _build_config(self):
        with open(self.files.dump) as istr:
            asm = x86AsmData(self.files.dump, istr)
        if os.path.isfile(self.files.dumptbl):
            with open(self.files.dumptbl) as istr:
                asm.read_symbol_table(istr)
        with open(self.files.bconfig, 'w') as ostr:
            self.ruleset.write_binsec_config(ostr, asm)
        with open(self.files.bmemory, 'w') as ostr:
            self.ruleset.write_binsec_memory(ostr, asm, self.context['symbols'])
        with open(self.files.rconfig, 'w') as ostr:
            self.ruleset.write_robust_config(ostr, asm)
        self.context['controlled'] = set()
        with open(self.files.rmemory, 'w') as ostr:
            self.ruleset.write_robust_memory(ostr, asm, self.context['symbols'], self.args.auto_control_variables, ctrlout=self.context['controlled'])
        with open(self.files.adirectives, 'w') as ostr:
            self.ruleset.write_abduct_directives(ostr, asm)
        with open(self.files.aliterals, 'w') as ostr:
            self.ruleset.write_abduct_literals(ostr, asm, self.context['controlled'])
        self.context['assume-addr'] = self.ruleset.make_assumption_addr_param(asm)

    def _build_runner(self):
        with open(self.files.runner, 'w') as ostr:
            self.ruleset.write_runner(ostr, self.files.input, self.files.binary, self.files.bconfig, self.files.bmemory, stack=self.debug_stack)
        with open(self.files.rrunner, 'w') as ostr:
            self.ruleset.write_runner(ostr, self.files.input, self.files.binary, self.files.rconfig, self.files.rmemory, stack=self.debug_stack)
        with open(self.files.arunner, 'w') as ostr:
            self.ruleset.write_abduction_runner(ostr, self.files.bconfig, self.files.rconfig, self.files.bmemory, self.files.binary,
                                                self.files.aliterals, self.files.adirectives, self.context['assume-addr'],
                                                self.args.binsec_timeout, autocontrol=self.args.auto_control_variables, stack=self.debug_stack)
        os.chmod(self.files.runner, 0o750)
        os.chmod(self.files.rrunner, 0o750)
        os.chmod(self.files.arunner, 0o750)
# ----------------------------------------
