# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy RED
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
Wrap Scapy's LDAPHero
"""

from scapy.config import conf
from scapy.modules.ldaphero import LDAPHero


def main():
    """
    Main entry point
    """
    from scapy.utils import AutoArgparse

    conf.exts.load("scapy-red")
    AutoArgparse(LDAPHero)


# For autocompletion generation
AUTOCOMPLETE_GEN = LDAPHero

if __name__ == "__main__":
    main()
