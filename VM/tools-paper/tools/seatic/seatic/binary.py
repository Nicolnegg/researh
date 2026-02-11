# --------------------
import re
import io
from pulseutils.assembly import ArmAsmData
from .core import Task, SystemTask
from .armasm import GenericObjDumpTask, ArmAsmDataCache
# --------------------
class AssCodeGenerationTask(GenericObjDumpTask):

    def __init__(self, ctx, logger, mutant=None):
        source = ctx['source'] if mutant is None else mutant
        target = ctx['target.assembly'] if mutant is None else ctx.mutant_assfile(mutant)
        super().__init__(ctx, source, target, logger)
# --------------------
class ObjdumpHeadersParser:

    def __init__(self, data):
        self.sections = {}
        self._parse(data)

    def _parse(self, data):
        with io.StringIO(data) as stream:
            for line in stream:
                self._parse_hline(line.strip())

    def _parse_hline(self, line):
        lhook = r'\d+\s+([.][.A-Za-z_]+)\s+([0-9a-f]{8})\s+([0-9a-f]{8})\s+([0-9a-f]{8})\s+([0-9a-f]{8})\s+([0-9]+[*]{2}[0-9]+)'
        lmatch = re.match(lhook, line)
        if lmatch:
            self.sections[lmatch[1]] = { 'size': lmatch[2], 'vma': lmatch[3], 'lma': lmatch[4], 'offset': lmatch[5], 'align': lmatch[6] }
# --------------------
class GetSourceInfoTask(GenericObjDumpTask):

    def __init__(self, ctx, logger):
        super().__init__(ctx, ctx['source'], ctx['target.assembly-headers'], logger, mainswitch='-h')

    def _execute(self):
        self.log.info('extracting {} headers'.format(self.ctx['source']))
        super()._execute()

    def _postprocess(self):
        super()._postprocess()
        parser = ObjdumpHeadersParser(self.output)
        try:
            self.ctx['source-info.text-offset'] = int(parser.sections['.text']['offset'], 16)
            self.log.info('detected .text offset in {}: 0x{:x}'.format(self.ctx['source'], self.ctx['source-info.text-offset']))
        except KeyError as e:
            self.log.error('could not find required {} section in {}'.format(e, self.ctx['source']))
# --------------------
class GetMutantInfoTask(AssCodeGenerationTask):

    def __init__(self, ctx, mutant, mutant_data, logger):
        super().__init__(ctx, logger, mutant)
        self.mutant = mutant
        self.data = mutant_data
        self.source_data = ArmAsmDataCache(self.ctx['source'], self.ctx, self.log)

    def should_discard(self):
        return len(self.data['skip-locs']) != self.ctx['mutation.cpt'] or (-1 in self.data['skip-locs'])

    def should_run(self):
        return True

    def _preprocess(self):
        super()._preprocess()

    def _execute(self):
        super()._execute()
        mutant_data = ArmAsmData(self.mutant, self.output, self.log)
        if not self.ctx['opt.task_logging']:
            self._clear_output()
        self._recover_skip_locations(mutant_data)
        if not self.should_discard():
            self._recover_skip_instructions()
            self._recover_memory_map(mutant_data)

    def _recover_memory_map(self, mdata):
        memory = {}
        for section in ('.bss', '.data'):
            if mdata.has_section(section):
                memory.update(mdata.as_memory(section))
        self.data['memory'] = memory

    def _recover_skip_locations(self, mdata):
        if not self.source_data.has_section('.text') or not mdata.has_section('.text'):
            self.log.error('no .text section in assembly file')
        if not self.source_data.matches_labels_of(mdata, '.text'):
            self.log.warning('source and mutant assembly maps strongly differ')
        skip_locs = mdata.get_skip_locs(self.source_data)
        self.log.debug('mutant {} skips @{}'.format(self.mutant, skip_locs))
        self.data['skip-locs'] = skip_locs

    def _recover_skip_instructions(self):
        skip_locs = self.data['skip-locs']
        skip_insts = tuple((self.source_data.get_instruction(loc) for loc in skip_locs))
        self.data['skip-insts'] = skip_insts
# --------------------
