from setuptools import setup

setup(name='c2binsec',
        version='0.1',
        description='compile c verif problems to binsec tasks',
        url='',
        author='Yanis Sellami',
        author_email='yanis.sellami@cea.fr',
        licence='None',
        packages=['c2binsec', 'c2binsec.ruleset'],
        scripts=['c2bc', 'c2ba'],
        install_requires=['colorama', 'tqdm', 'pycparser', 'pyyaml',
            'pulseutils @ git+ssh://git@git-dscin.intra.cea.fr/pulse-ia/pulseutils.git'],
        include_package_data=True,
        zip_safe=False)
