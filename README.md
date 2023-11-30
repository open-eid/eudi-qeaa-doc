# EUDI Qualified Electronic Attestations of Attributes Provider Technical Documentation

Documentation is written using [MkDocs](http://www.mkdocs.org/) static documentation site generator
with [Material theme](https://squidfunk.github.io/mkdocs-material/)
and [Markdown](https://daringfireball.net/projects/markdown/).

## Requirements

* **Python 3**
* **pip** - Python package manager
* **Text Editor** - to edit Markdown documents (i.e [Haroopad](http://pad.haroopress.com/#))

## Installing required software

### Both Ubuntu and Mac OS X come `python` already installed (the version depends on OS)

1. Install `pip` on Ubuntu `sudo apt-get install python-pip` on Mac OS X `sudo easy_install pip`
2. Install required components `pip install -r requirements.txt`

### Windows

1. Install python. Download the installer from the official `python` homepage: <https://www.python.org/downloads/> and
   install

> **NOTE:** Starting with version 2.7.9 and onwards `pip` ships along with python, so there shouldn't be any need to
> install `pip` separately.

2. Install required components `pip install -r requirements.txt`

## Editing content

1. Edit markdown files inside the `docs` directory
2. Preview Your changes by issuing `mkdocs serve` in project root and navigating to <http://localhost:8000>
3. Build assembled documentation `eudi-qeaa-issuer.md` by issuing `mkdocs build` in project root 
4. Commit and push Your changes to `git`
