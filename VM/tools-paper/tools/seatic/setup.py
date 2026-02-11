from setuptools import setup

setup(name='seatic',
        version='0.2',
        description='',
        url='',
        author='',
        author_email='',
        licence='',
        packages=['seatic', 'seatic.data.core', 'seatic.data.docker', 'seatic.data.configs', 'seatic.data.configs.fissc'],
        scripts=['bin/seatic', 'bin/survival-plotter', 'bin/pyabdlog'],
        install_requires=['colorama', 'pyyaml', 'tqdm', 'jinja2', 'matplotlib', 'scipy',
            'pulseutils @ git+ssh://git@git-dscin.intra.cea.fr/pulse-ia/pulseutils.git'],
        include_package_data=True,
        package_data={'seatic': ['data/docker/*.dockerfile', 'data/docker/*.yml', 'data/docker/container-start*',
                                 'data/core/*.yml', 'data/configs/fissc/*.j2']},
        zip_safe=False)
