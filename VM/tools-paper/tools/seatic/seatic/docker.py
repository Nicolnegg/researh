# --------------------
import sys, os, shutil
try:
    import importlib.resources as resources
except ImportError:
    import importlib_resources as resources
from subprocess import Popen, STDOUT, PIPE
# --------------------
RECIPES = ('qemu', 'objdump', 'gcc-32', 'boolector', 'ninja')
CONTAINERS = ('binsec-builder', 'packages-builder')
RESOURCES = ('container-start-add', 'container-start-mod') + tuple(('{}.dockerfile'.format(c) for c in CONTAINERS)) + tuple(('{}.recipe.yml'.format(c) for c in RECIPES))
# --------------------
def docker_image(container):
    return 'seatic-{}'.format(container)
# --------------------
class DockerRunner:

    def __init__(self, buildpath, logger):
        self.log = logger
        self.buildpath = buildpath
        self.uid = os.geteuid()
        self.gid = os.getegid()
        self.statuses = { c : None for c in CONTAINERS }
        self.initialize()

    def __del__(self):
        self.terminate()

    def build_docker_buildpath(self):
        if not os.path.isdir(self.buildpath):
            self.log.debug('creating virtual build path in {}'.format(self.buildpath))
            os.makedirs(self.buildpath)
        for resource in RESOURCES:
            with resources.path('seatic.data.docker', resource) as source:
                self.log.debug('copying {} -> {}'.format(source, self.buildpath))
                shutil.copy(source, self.buildpath)

    def get_dockerfile_version(self, dockerfile):
        stream = open(dockerfile)
        version = None
        for line in stream:
            if line.startswith('ARG\tsdcversion'):
                version = int(line.strip().split('=')[1])
                break
        stream.close()
        return version

    def _run_command(self, cmd, capture=True):
        proc = Popen(cmd, stdout=(PIPE if capture else sys.stdout), stderr=(STDOUT if capture else sys.stderr))
        cout, cerr = proc.communicate()
        pcout = cout.decode(sys.stdout.encoding).strip() if cout is not None else None
        return proc.returncode, pcout

    def get_container_version(self, container):
        cmd = ['docker', 'run', '-it', '--rm',
                '--env', 'LOCAL_USER_ID={}'.format(self.uid),
                docker_image(container), 'seatic-version-ping']
        rc, cout = self._run_command(cmd)
        if rc != 0:
            return cout
        try:
            return int(cout)
        except:
            return '{} is NaN'

    def ping_container(self, container):
        self.log.check('pinging container {}'.format(container))
        dockerfile = os.path.join(self.buildpath, '{}.dockerfile'.format(container))
        dockerfile_version = self.get_dockerfile_version(dockerfile)
        mounted_version = self.get_container_version(container)
        valid = isinstance(mounted_version, int) and mounted_version >= dockerfile_version
        self.log.check_end(valid)
        self.log.debug('container ping result: {} <= {}'.format(dockerfile_version, mounted_version))
        return valid

    def build_container(self, container):
        self.log.info('building container {} (may take a while)'.format(container))
        dockerfile = os.path.join(self.buildpath, '{}.dockerfile'.format(container))
        cmd = ['docker', 'build', '--tag', docker_image(container), '--file', dockerfile, self.buildpath]
        rc, cout = self._run_command(cmd, capture=False)
        if rc != 0:
            raise RuntimeError('failed to build virtual container {}: {}'.format(container, rc))

    def start_container(self, container):
        self.log.check('starting container {}'.format(container))
        cmd = ['docker', 'run', '-d',
                '--volume', '{}:/homedir'.format(os.getcwd()),
                '--env', 'LOCAL_USER_ID={}'.format(self.uid),
                docker_image(container), 'sleep', 'infinity']
        rc, cout = self._run_command(cmd)
        cid = cout
        valid = rc == 0
        self.log.check_end(valid, cid)
        if not valid:
            raise RuntimeError('failed to start virtual container {}: {}'.format(container, rc))
        return cid

    def stop_container(self, container, trailing=False):
        self.log.check('stopping {}container {}'.format('trailing ' if trailing else '', container))
        cid = container if trailing else self.statuses[container]
        cmd = ['docker', 'stop', cid]
        rc, cout = self._run_command(cmd)
        valid = rc == 0
        self.log.check_end(valid)
        if not valid:
            self.log.warning('failed to stop container {} ({})'.format(container, cid))

    def remove_container(self, container, trailing=False):
        self.log.check('removing {}container {}'.format('trailing ' if trailing else '', container))
        cid = container if trailing else self.statuses[container]
        cmd = ['docker', 'rm', cid]
        rc, cout = self._run_command(cmd)
        valid = rc == 0
        self.log.check_end(valid)
        if not valid:
            log.warning('failed to remove container {} ({})'.format(container, cid))

    def run_container(self, container, command, capture=True):
        self.log.check('running "{}" in container {}'.format(' '.join(command), container))
        cmd  = ['docker', 'run', '-it', '--rm',
                '--volume', '{}:/homedir'.format(os.getcwd()),
                '--env', 'LOCAL_USER_ID={}'.format(self.uid),
                '--env', 'LOCAL_GROUP_ID={}'.format(self.gid),
                docker_image(container)]
        cmd.extend(command)
        rc, cout = self._run_command(cmd, capture)
        valid = rc == 0
        self.log.check_end(valid)
        if not valid:
            self.log.warning('command {} failed in container {}'.format(' '.join(command), container))

    def initialize(self):
        self.build_docker_buildpath()

    def terminate(self):
        pass
# --------------------
