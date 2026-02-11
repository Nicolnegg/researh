from setuptools import setup

setup(name='fistic',
        version='0.2',
        description='fault injection simulator',
        url='',
        author='Thierno Barry',
        author_email='thierno.barry@cea.fr',
        licence='CeCILL-B',
        packages=['fistic', 'fistic/evaluators', 'fistic/faulters', 'fistic/placers'],
        scripts=['fistic-core', 'fistic-mapper'],
        install_requires=['configparser', 'colorama', 'tqdm', 'pyyaml',
            'pytest', 'pytest-cov', 'pytest-console-scripts', 'pytest-sugar',
            'sphinx', 'sphinx-autoapi',],
        include_package_data=True,
        zip_safe=False)
