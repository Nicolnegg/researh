# --------------------
import sys, os, shutil
try:
    import importlib.resources as resources
except ImportError:
    import importlib_resources as resources
from subprocess import Popen, STDOUT, PIPE
from .engine import SeaticBaseRunner
from .docker import DockerRunner
from . import docker
# --------------------
class ToolGenerator:

    def __init__(self, ctx, logger):
        self.ctx = ctx
        self.log = logger
        self.buildpath = os.path.abspath(self.ctx['opt.docker_buildpath'])
        self.drunner = DockerRunner(self.buildpath, self.log)

    def generate(self):
        self._clone_repositories()
        self._build_tools()
        self._install_tools()

    def _clone_repositories(self):
        for distant, local, ref in (('git@git.frama-c.com:grenoble/binsec.git', 'binsec-src', 'feature/se/blast'),
                                    ('git@git.frama-c.com:unisim-vp/unisim.git', 'unisim-src', 'binsec-dev'),
                                    ('https://github.com/binsec/cav2021-artifacts.git', 'cav20-src', 'main')):
            rc, out = self.drunner._run_command(['git', 'clone', '--branch', ref, distant, os.path.join(self.buildpath, local)], capture=False)
            if rc != 0:
                self.log.error('failed to clone branch {} of {}'.format(ref, distant))

    def _build_tools(self):
        for container in docker.CONTAINERS:
            if not container in self.ctx['opt.skip_container']:
                self.drunner.build_container(container)

    def _install_tools(self):
        for tool, appimage, container in (('binsec', 'binsec-x86_64.AppImage', 'binsec-builder'),
                                          ('qemu-system-arm', 'qemu-system-arm-latest-x86_64.AppImage', 'packages-builder'),
                                          ('gcc-32dk', 'gcc-latest-x86_64.AppImage', 'packages-builder'),
                                          ('boolector', 'boolector-latest-x86_64.AppImage', 'packages-builder'),
                                          ('ninja', 'ninja-latest-x86_64.AppImage', 'packages-builder'),
                                          ('arm-objdump', 'arm-none-eabi-objdump-latest-x86_64.AppImage', 'packages-builder')):
            if container in self.ctx['opt.skip_container']:
                continue
            local_tool = os.path.join(self.buildpath, tool)
            container_tool = os.path.join('/homedir', tool)
            container_appimage = os.path.join('/', appimage)
            self.drunner.run_container(container, ['cp', container_appimage, container_tool])
            self.drunner.run_container('packages-builder', ['chown', '{}:{}'.format(self.drunner.uid, self.drunner.gid), container_tool])
            self.drunner.run_container('packages-builder', ['chmod', '775', container_tool])
            self.log.info('copying {} -> {}'.format(tool, local_tool))
            shutil.move(tool, local_tool)
            self.log.info('updating context for {}'.format(tool))
            self.ctx['tool'][tool] = local_tool
# --------------------
class ToolGeneratorRunner(SeaticBaseRunner):
    
    def __init__(self, args, **kwargs):
        super().__init__(args, **kwargs)
        self.engine = ToolGenerator(self.ctx, self.log)

    def run(self):
        self.log.info('running tool generator')
        self.engine.generate()
        super().run()
# --------------------
class ToolCheckerRunner(SeaticBaseRunner):
    pass
# --------------------
