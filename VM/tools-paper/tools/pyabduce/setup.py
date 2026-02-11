from setuptools import setup

setup(name='pyabduction',
        version='0.1',
        description='python abduction solver',
        url='',
        author='Yanis Sellami',
        author_email='yanis.sellami@cea.fr',
        licence='None',
        packages=['pyabduction'],
        scripts=['pyabduce', 'pyabduce-sat'],
        install_requires=['colorama', 'tqdm', 'configparser', 'cvc5',
            'pulseutils @ git+ssh://git@git-dscin.intra.cea.fr/pulse-ia/pulseutils.git'],
        include_package_data=True,
        zip_safe=False)
