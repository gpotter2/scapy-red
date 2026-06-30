# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy RED
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
Scapy RED plugin
"""

import pathlib

__version__ = "0.0.4"


def scapy_ext(pkg):
    pkg.config("Scapy RED", __version__)

    # Imports modules that have hooks
    import scapyred.krbingest

    # Add completions
    for completion in (pathlib.Path(__file__).parent / "completions").glob("scapy-*"):
        pkg.register_bashcompletion(completion)
