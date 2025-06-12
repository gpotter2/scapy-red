#! /usr/bin/env python

# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy RED
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
Setuptools setup file for Scapy.
"""

import sys

if sys.version_info < (3, 11):
    raise OSError("Scapy RED needs Python 3.11+ !")

import importlib
import io
import os
import pathlib
import tomllib

try:
    from setuptools import setup
    from setuptools.command.sdist import sdist
    from setuptools.command.build_py import build_py
except:
    raise ImportError("setuptools is required to install Scapy RED !")

try:
    from scapy.utils import AutoArgparse
except:
    raise ImportError("scapy is required to install Scapy RED !")


def get_long_description():
    """
    Extract description from README.md, for PyPI's usage
    """

    def process_ignore_tags(buffer):
        return "\n".join(
            x for x in buffer.split("\n") if "<!-- ignore_ppi -->" not in x
        )

    try:
        fpath = os.path.join(os.path.dirname(__file__), "README.md")
        with io.open(fpath, encoding="utf-8") as f:
            readme = f.read()
            desc = readme.partition("<!-- start_ppi_description -->")[2]
            desc = desc.partition("<!-- stop_ppi_description -->")[0]
            return process_ignore_tags(desc.strip())
    except IOError:
        return None


def _build_completions(dest):
    """
    Generate then return a list of bash autocompletion files
    """
    # Local folder to read templates from
    local = pathlib.Path(__file__).parent / "scapyred" / "completions"

    # Destination folder
    completions = pathlib.Path(dest) / "scapyred" / "completions"
    if not completions.exists():
        completions.mkdir()

    # Read list of scripts
    with open("pyproject.toml", "rb") as f:
        data = tomllib.load(f)

    # Read the two templates
    with open(local / "template_complete.bash") as fd:
        COMPLETE_SCRIPT = fd.read()

    with open(local / "template_script.bash") as fd:
        TEMPLATE = fd.read()

    fmtargs = lambda x: " ".join('"%s"' % y for y in x)

    # Make import_module work (ugly)
    sys.path.append(str(pathlib.Path(__file__).parent))

    # For each script, create a completion script.
    for script, entry in data["project"]["scripts"].items():
        fpath = completions / script
        with open(fpath, "w") as fd:
            # Get function
            mod = importlib.import_module(entry.split(":")[0])
            try:
                function = mod.AUTOCOMPLETE_GEN
            except AttributeError:
                # Autocompletion is not available.
                continue

            # Get completion arguments
            all_completion_arguments, noarguments_completion_arguments = AutoArgparse(
                function,
                _parseonly=True,
            )

            # Append util function
            fd.write(COMPLETE_SCRIPT)

            # Append script template
            fd.write(
                TEMPLATE.format(
                    script_name=script,
                    all_completion_arguments=fmtargs(all_completion_arguments),
                    noarguments_completion_arguments=fmtargs(
                        noarguments_completion_arguments
                    ),
                )
            )


class SDist(sdist):
    """
    Modified sdist to create completions
    """

    def make_release_tree(self, base_dir, *args, **kwargs):
        super(SDist, self).make_release_tree(base_dir, *args, **kwargs)
        # ensure completions are generated
        _build_completions(base_dir)


class BuildPy(build_py):
    """
    Modified build_py to create completions
    """

    def build_package_data(self):
        super(BuildPy, self).build_package_data()
        # ensure completions are generated
        _build_completions(self.build_lib)


setup(
    cmdclass={"sdist": SDist, "build_py": BuildPy},
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
)
