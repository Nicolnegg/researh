from setuptools import setup

setup(name='pulseutils',
        version='0.1',
        description='python utils for pulse',
        url='',
        author='Yanis Sellami',
        author_email='yanis.sellami@cea.fr',
        licence='',
        packages=['pulseutils'],
        scripts=['bin/capsule-run', 'bin/generate-binsec-config'],
        install_requires=['colorama', 'pyyaml', 'tqdm'],
        include_package_data=True,
        zip_safe=False)
