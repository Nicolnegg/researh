# --------------------
import re
import io
from pulseutils.assembly import ArmAsmData, ArmAsmFile
from .core import SystemTask
# --------------------
class GenericObjDumpTask(SystemTask):

    def __init__(self, ctx, source, target, logger, mainswitch='-D'):
        cmd = [ctx['tool.arm-objdump'], mainswitch, source]
        super().__init__(cmd, logger)
        self.ctx = ctx
        self.source = source
        self.target = target

    def _postprocess(self):
        if self.ctx['opt.task_logging']:
            self._log_output(self.target)
# --------------------
DataCache = dict()
FileCache = dict()
# --------------------
def ArmAsmFileCache(filename):
    global FileCache
    if not filename in FileCache:
        FileCache[filename] = ArmAsmFile(filename)
    return FileCache[filename]
# --------------------
def ArmAsmDataCache(source, ctx, logger):
    global DataCache
    if not source in DataCache:
        loader = GenericObjDumpTask(ctx, source, ctx['temp.assembly'], logger)
        loader.execute()
        DataCache[source] = ArmAsmData(source, loader.output, logger)
    return DataCache[source]
# --------------------
