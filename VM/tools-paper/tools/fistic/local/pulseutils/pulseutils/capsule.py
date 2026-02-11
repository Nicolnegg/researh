# ----------------------------------------
import os
import shutil
import zipfile
import yaml
try:
    from yaml import CLoader as ymlLoader, CDumper as ymlDumper
except ImportError:
    from yaml import Loader as ymlLoader, Dumper as ymlDumper
from pulseutils.logging import Logger
# ----------------------------------------
class Capsule:

    def __init__(self, path, config=None):
        self.path = path
        configfile = config if config is not None else os.path.join(path, 'config.yml')
        with open(configfile, 'r') as strem:
            self.config = yaml.load(stream, Loader=ymlLoader)['capsule']

    def __call__(self, source, target):
        source = os.path.abspath(source)
        target = os.path.abspath(target)
        localdir = os.getcwd()
        source_link = os.path.join(localdir, 'capsule', self.config['source'])
        target_link = os.path.join(localdir, 'capsule', self.config['target'])
        execdir = os.path.join(localdir, 'capsule', self.config['compiler']['directory']) # TODO; Netter directory recov
        cmd = self.config['compiler']['command']
        shutil.copyfile(source, source_link)
        os.chdir(execdir)
        os.system(cmd)
        os.chdir(localdir)
        shutil.copyfile(target_link, target)
# ----------------------------------------
class ZipCapsule(Capsule):

    def __init__(self, capsule):
        self.capsule = capsule
        self.path = None
        self.config = None

    def __call__(self, source, target):
        source = os.path.abspath(source)
        target = os.path.abspath(target)
        shutil.copyfile(self.capsule, '/tmp/capsule.zip')
        localdir = os.getcwd()
        os.chdir('/tmp')
        with zipfile.ZipFile('/tmp/capsule.zip', 'r') as zipref:
            zipref.extractall()
        self.path = '/tmp/capsule'
        configfile = '/tmp/capsule/config.yml'
        with open(configfile, 'r') as stream:
            self.config = yaml.load(stream, Loader=ymlLoader)['capsule']
        super().__call__(source, target)
        os.chdir(localdir)
# ----------------------------------------
