# Configuration file for the Sphinx documentation builder.
# See https://www.sphinx-doc.org/en/master/usage/configuration.html

project = "pyintrovirt"
copyright = "IntroVirt"
author = "IntroVirt"
release = "0.1.0"

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.viewcode",
]

autodoc_mock_imports = ["introvirt"]

templates_path = ["_templates"]
exclude_patterns = []

html_theme = "furo"
html_static_path = ["_static"]

html_theme_options = {
    "sidebar_hide_name": True,
}
