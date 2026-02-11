# --------------------
import os
import shutil
import jinja2 as j2
from .armasm import ArmAsmDataCache
from pulseutils.files import prefixate
# --------------------
class SeaticConfigGenerator:

    def __init__(self, ctx, bfile, outdir, logger):
        self.ctx = ctx
        self.bfile = bfile
        self.bdata = None
        self.outdir = outdir
        self.log = logger
        self.j2envs = {}
        self._load_bfile()

    def _load_bfile(self):
        self.log.info('disasm and loading binary file: {}'.format(self.bfile))
        target = self.outfile('{}.temp.s'.format(os.path.basename(self.bfile)))
        self.bdata = ArmAsmDataCache(self.bfile, self.ctx, self.log)

    def run(self):
        self._check_outdir()
        self._cp_binary()
        self._cp_vsimbinary()
        self._generate()

    def outfile(self, name):
        return os.path.join(self.outdir, os.path.basename(name))

    def template(self, submodule, name):
        if not submodule in self.j2envs:
            self.j2envs[submodule] = j2.Environment(loader=j2.PackageLoader('seatic.data.configs', submodule))
        return self.j2envs[submodule].get_template(name)

    def write_file(self, name, data):
        with open(self.outfile(name), 'w') as stream:
            stream.write(data)

    def _cp_binary(self):
        target = self.outfile(self.bfile)
        self.log.debug('copying {} -> {}'.format(self.bfile, target))
        shutil.copy(self.bfile, target)

    def _cp_vsimbinary(self):
        prefix = self.ctx['target.vsimulation-prefix']
        source = prefixate(self.bfile, prefix)
        target = prefixate(self.outfile(self.bfile), prefix)
        self.log.debug('copying {} -> {}'.format(source, target))
        try:
            shutil.copy(source, target)
        except FileNotFoundError:
            self.log.error('could not find vsimulation binary at {} --> skipped'.format(source))

    def _check_outdir(self):
        if not os.path.isdir(self.outdir):
            self.log.info('creating output directory: {}'.format(self.outdir))
            os.makedirs(self.outdir)

    def _generate(self):
        raise NotImplementedError(self)
# --------------------
class FISSCVerifyPINGenerator(SeaticConfigGenerator):

    def __init__(self, ctx, bfile, outdir, logger):
        super().__init__(ctx, bfile, outdir, logger)
        self._locs = {}
        self._targets = []
        self._memory = {}
        self._constants = set()

    def get_hex(self, v):
        return '0x{:x}'.format(v)

    def get_hex8(self, v):
        return '{:#010x}'.format(v)

    def get_hexloc(self, lid, offset=0):
        return self.get_hex(self._locs[lid] + offset)

    def get_hex8loc(self, lid, offset=0):
        return self.get_hex8(self._locs[lid] + offset)

    def _generate(self):
        self._detect_targets()
        self._detect_addresses()
        self._detect_memory()
        self._detect_constants()
        self._update_context()
        self._generate_file('vpin-binsec.config.j2', 'binsec.config')
        self._generate_file('vpin-binsec.mem.j2', 'binsec.mem')
        self._generate_file('vpin-robust.config.j2', 'robust.config')
        if self.ctx['opt.no_controlled_memory']:
            self._generate_file('vpin-robust.mem.noctrl.j2', 'robust.mem')
        else:
            self._generate_file('vpin-robust.mem.j2', 'robust.mem')
        self._generate_file('vpin-abducer.binsec.config.j2', 'abducer.binsec.config')
        self._generate_file('vpin-abducer.robust.config.j2', 'abducer.robust.config')
        self._generate_file('vpin-abducer.binsec.mem.j2', 'abducer.binsec.mem')
        self._generate_file('vpin-abducer.directives.txt.j2', 'abducer.directives.txt')
        self._generate_file('vpin-abducer.literals.txt.j2', 'abducer.literals.txt')
        self._generate_file('vpin-simulation-initpkg.py.j2', '__init__.py')
        self._generate_file('vpin-simulation-matcher.py.j2', 'wsim.py', mode=0o750)
        self._generate_file('vpin-vsimulation-core.bash.j2', 'qemu-simulate.bash', mode=0o750)
        self._generate_file('vpin-vsimulation-wrapper.bash.j2', 'generate-simulation-log.bash', mode=0o750)
        self._generate_contextfile()

    def _detect_addresses(self):
        for label in ('g_countermeasure', 'g_ptc', 'g_authenticated', 'g_userPin', 'g_cardPin'):
            try:
                self._locs[label] = self.bdata.address_of(label, '.bss')
            except KeyError:
                self._locs[label] = self.bdata.address_of(label, '.data')
        ctarget = [v for v in self._targets if v.startswith('verifyPIN')][0]
        call_loc, reach_loc, reach_loc_n, cut_loc, init_loc = None, None, None, None, None
        for loc, inst in self.bdata.instructions('capsule', '.text'):
            if init_loc is None and loc != self.bdata.address_of('capsule', '.text'):
                init_loc = loc
            if call_loc is None and '<{}>'.format(ctarget) in inst:
                call_loc = loc
            if '\tbx\t' in inst or '\tpop\t' in inst:
                if cut_loc is not None:
                    self.log.warning('multiple fissc vpin cut locs found: disc. {}, keeping last'.format(cut_loc))
                cut_loc = loc
            if '\tadds\t' in inst:
                if '#3' in inst:
                    if reach_loc is not None:
                        self.log.warning('multiple fissc vpin reach locs found: disc. {} keeping last'.format(reach_loc))
                    reach_loc = loc
                if '#7' in inst:
                    if reach_loc_n is not None:
                        self.log.warning('multiple fissc vpin negated reach locs found: disc. {} keeping last'.format(reach_loc_n))
                    reach_loc_n = loc
        if call_loc is None:
            self.log.warning('no call location found in binary')
        if reach_loc is None:
            self.log.warning('no reach location found in binary')
        if reach_loc_n is None:
            self.log.warning('no reach negation location found in binary')
        if cut_loc is None:
            self.log.warning('no cut location found in binary')
        if init_loc is None:
            self.log.warning('no init location found in binary')
        self._locs['@init'] = init_loc
        self._locs['@call'] = call_loc
        self._locs['@reach'] = reach_loc
        self._locs['@reach-negation'] = reach_loc_n
        self._locs['@cut'] = cut_loc

    def _detect_targets(self):
        for target in ('byteArrayCompare', 'verifyPIN_A', 'verifyPIN_1', 'verifyPIN_2', 'verifyPIN_3', 'verifyPIN_4', 'verifyPIN_5', 'verifyPIN_6', 'verifyPIN_7'):
            if self.bdata.has_function(target):
                self.log.info('detected fissc verifyPin target: {}'.format(target))
                self._targets.append(target)

    def _detect_memory(self):
        for target in self._targets:
            self._memory.update(self.bdata.literals(label=target))
        for clabel in ('capsule', 'countermeasure'):
            # TODO: Automatically detect called functions and update memory
            if self.bdata.has_function(clabel):
                self._memory.update(self.bdata.literals(label=clabel))

    def _detect_constants(self):
        for _, val in self._memory.items():
            self._constants.add(val)
        for target in self._targets:
            self._constants.update(self.bdata.ininstr_constants(label=target))

    def _generate_file(self, template, target, mode=None):
        template = self.template('fissc', template)
        target = self.outfile(target)
        self.log.info('generating {}'.format(target))
        with open(target, 'w') as stream:
            stream.write(template.render(data=self))
            stream.write('\n') # To avoid parsing errors in binsec memory files
        if mode is not None:
            os.chmod(target, mode)

    def _update_context(self):
        self.log.info('updating context')
        self.ctx['mutation.targets'] = self._targets
        self.ctx['oracle.reach'] = self._locs['@reach']
        self.ctx['oracle.reach-negation'] = self._locs['@reach-negation']
        self.ctx['abduction.depth'] = 4
        self.ctx['abduction.address'] = self._locs['@init']
        self.ctx['source'] = self.outfile(self.bfile)
        self.ctx['config.binsec'] = self.outfile('binsec.config')
        self.ctx['config.binsec-memory'] = self.outfile('binsec.mem')
        self.ctx['config.binsec-robust'] = self.outfile('robust.config')
        self.ctx['config.binsec-robust-memory'] = self.outfile('robust.mem')
        self.ctx['config.abducer-binsec-config'] = self.outfile('abducer.binsec.config')
        self.ctx['config.abducer-robust-config'] = self.outfile('abducer.robust.config')
        self.ctx['config.abducer-binsec-memory'] = self.outfile('abducer.binsec.mem')
        self.ctx['config.abducer-directives'] = self.outfile('abducer.directives.txt')
        self.ctx['config.abducer-literals'] = self.outfile('abducer.literals.txt')
        self.ctx['config.vsimulation-script'] = self.outfile('wsim.py')
        self.ctx['config.vsimulation-qemu-script'] = self.outfile('qemu-simulate.bash')
        self.ctx['config.vsimulation-wrap-script'] = self.outfile('generate-simulation-log.bash')

    def _generate_contextfile(self):
        data = {
            'tool': self.ctx['tool'],
            'environ': self.ctx['environ'],
            'mutation': self.ctx['mutation'],
            'abduction': self.ctx['abduction'],
            'oracle': self.ctx['oracle'],
            'source': self.ctx['source'],
            'config': self.ctx['config'],
            'target': self.ctx['target'],
            'log': self.ctx['log'],
        }
        target = self.outfile('context.yml')
        self.log.info('generating minimal seatic context file: {}'.format(target))
        import yaml
        try:
            from yaml import CDumper as ymlDumper
        except ImportError:
            from yaml import Dumper as ymlDumper
        with open(target, 'w') as stream:
            yaml.dump(data, stream, Dumper=ymlDumper)
# --------------------
CONFIGURATOR_DB = {
    'fissc-verifypin': FISSCVerifyPINGenerator,
}
# --------------------
def get_configurator(cid, ctx, bfile, outdir, logger):
    if cid in CONFIGURATOR_DB:
        return CONFIGURATOR_DB[cid](ctx, bfile, outdir, logger)
    else:
        logger.critical('unknown configuration generator: {}'.format(cid))
# --------------------
