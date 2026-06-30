# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy RED
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
Ingest a .ccache into Windows
"""

import ctypes

from scapy.config import conf
from scapy.consts import WINDOWS
from scapy.modules.ticketer import Ticketer

KerbSubmitTicketMessage = 21


class LUID(ctypes.Structure):
    _fields_ = [
        ("LowPart", ctypes.c_ulong),
        ("HighPart", ctypes.c_long),
    ]


class KERB_CRYPTO_KEY32(ctypes.Structure):
    _fields_ = [
        ("KeyType", ctypes.c_long),
        ("Length", ctypes.c_ulong),
        ("Offset", ctypes.c_ulong),
    ]


class KRB_SUBMIT_TKT_REQUEST(ctypes.Structure):
    _fields_ = [
        ("MessageType", ctypes.c_ulong),
        ("LogonId", LUID),
        ("Flags", ctypes.c_ulong),
        ("Key", KERB_CRYPTO_KEY32),
        ("KerbCredSize", ctypes.c_ulong),
        ("KerbCredOffset", ctypes.c_ulong),
    ]


def krbingest(
    t: Ticketer = None,
    ccache_path: str = None,
):
    """
    Ingest a CCACHE file into the Windows ticket store.

    Note: if trying to inject multiple tickets, the UPN must be exactly
    the same for all tickets. Most notably, it is cap sensitive in this case.

    :param t: the Ticketer object to ingest
    :param ccache_path: the path to the ccache file to ingest
    """
    if not WINDOWS:
        raise OSError("Ingesting tickets is only available on Windows !")

    from scapy.arch.windows.sspi import WinSSP

    # Util
    winssp = WinSSP()

    if t is None:
        # Open ccache
        if ccache_path is None:
            raise ValueError("Please provide either 't' or 'ccache_path'.")

        t = Ticketer()
        t.open_ccache(ccache_path)

    # Build request
    krb_cred = t.ccache.toKRBCRED()
    req = KRB_SUBMIT_TKT_REQUEST()
    req.MessageType = KerbSubmitTicketMessage
    req.LogonId = LUID()  # 0
    req.Flags = 0
    req.KerbCredSize = len(krb_cred)
    req.KerbCredOffset = ctypes.sizeof(KRB_SUBMIT_TKT_REQUEST)
    ProtocolSubmitBuffer = ctypes.create_string_buffer(bytes(req) + bytes(krb_cred))

    # Send
    Handle = winssp._LsaConnectUntrusted()
    try:
        AuthenticationPackage = winssp._LsaLookupAuthenticationPackage(
            Handle, "Kerberos"
        )
        winssp._LsaCallAuthenticationPackage(
            Handle, AuthenticationPackage, ProtocolSubmitBuffer
        )
    finally:
        winssp._LsaDeregisterLogonProcess(Handle)

    print("SUCCESS")


def main():
    """
    Main entry point
    """
    from scapy.utils import AutoArgparse

    conf.exts.load("scapy-red")
    AutoArgparse(krbingest)


# We also inject a function inside Ticketer
def ingest(self):
    """
    Ingest the current ticket store inside Windows.

    Note: if trying to inject multiple tickets, the UPN must be exactly
    the same for all tickets. Most notably, it is cap sensitive in this case.
    """
    krbingest(self)


Ticketer.ingest = ingest


# For autocompletion generation
AUTOCOMPLETE_GEN = krbingest

if __name__ == "__main__":
    main()
