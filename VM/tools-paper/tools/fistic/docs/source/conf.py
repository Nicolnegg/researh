# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = 'Fistic'
copyright = '2023, Thierno Barry, Yanis Sellami'
author = 'Thierno Barry, Yanis Sellami'
release = '0.3.0'

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

#import pathlib
#import sys
#sys.path.insert(0, pathlib.Path(__file__).parents[2].resolve().as_posix())

extensions = [
    'sphinx.ext.todo',
    'autoapi.extension',
]
autoapi_dirs = ['../../fistic']
autoapi_options = ['members', 'undoc-members', 'private-members', 'show-inheritance', 'show-module-summary', 'special-members', 'imported-members', 'inherited-members']

templates_path = ['_templates']
exclude_patterns = []



# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'sphinxdoc'
html_static_path = ['_static']
