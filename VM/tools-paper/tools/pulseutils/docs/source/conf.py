# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = 'PulseUtils'
copyright = '2023, Yanis Sellami'
author = 'Yanis Sellami'
release = '0.1'

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    'sphinx.ext.todo',
    'sphinx.ext.mathjax',
    'autoapi.extension',
]
autoapi_dirs = ['../../pulseutils']
autoapi_options = ['members', 'undoc-members', 'private-members', 'show-inheritance', 'show-module-summary', 'special-members', 'imported-members', 'inherited-members']

templates_path = ['_templates']
exclude_patterns = []



# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'sphinxdoc'
html_static_path = ['_static']
