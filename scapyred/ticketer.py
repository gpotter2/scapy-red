# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy RED
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
Command-line wrapper over Scapy's 'ticketer' module
"""

import enum
import os
import pathlib

from scapy.config import conf
from scapy.modules.ticketer import Ticketer
from scapy.libs.rfc3961 import Key, EncryptionType


class TicketerCliAction(enum.StrEnum):
    REQUEST_TGT = "request_tgt"
    REQUEST_ST = "request_st"
    SHOW = "show"
    REMOVE_KRB = "remove_krb"


def ticketercli(
    action: TicketerCliAction,
    *,
    ccache: str = None,
    upn: str = None,
    spn: str = None,
    i: int = None,
    ip: str = None,
    password: str = None,
    realm: str = None,
    HashNt: bytes = None,
    HashAes256Sha96: bytes = None,
    HashAes128Sha96: bytes = None,
    renew: bool = False,
    armor_with: int = None,
    for_user: str = None,
    s4u2proxy: int = None,
    x509: str = None,
    x509key: str = None,
    p12: str = None,
    host: str = "WIN11",
    debug: int = 0,
):
    r"""
    Command-line wrapper over Scapy's 'ticketer' module. This can be used to request
    TGTs and STs, perform advanced requests (S4U2Self, S4U2Proxy, etc.).

    This is provided for convenience, more examples are available in 'ticketer' !
    https://scapy.readthedocs.io/en/latest/layers/kerberos.html#ticketer-module

    EXAMPLES

    Example: get TGT

        $ export KRB5CCNAME="administrator.ccache"
        $ scapy-ticketer request_tgt --upn "Administrator@domain.local" --password "Password123!"
        $ scapy-ticketer request_tgt --upn "Administrator@domain.local" --HashAes256Sha96 4d6ca4e629785c1f01baf55e2e548566b9617ae3a96868c337cb93b5e72b1c7b
        $ scapy-ticketer request_tgt --upn "Administrator@domain.local" --HashNt 24d7f6b6bae4e5c00d2082c5ebab3672

    Example: show tickets
        $ export KRB5CCNAME="administrator.ccache"
        $ scapy-ticketer show

    Example: get ST with TGT n°0
        $ export KRB5CCNAME="administrator.ccache"
        $ scapy-ticketer request_st --i 0 --spn "cifs/dc1.domain.local"

    Example: remove ticket n°2
        $ export KRB5CCNAME="administrator.ccache"
        $ scapy-ticketer remove_krb --i 2

    Example: S4U2Self
        $ export KRB5CCNAME="administrator.ccache"
        $ scapy-ticketer request_tgt --upn "MACHINE01$@domain.local" --HashAes256Sha96 4d6ca4e629785c1f01baf55e2e548566b9617ae3a96868c337cb93b5e72b1c7b
        $ scapy-ticketer request_st --i 0 --spn "cifs/MACHINE01" --for-user "Administrator@domain.local"

    :param upn: the user principal name formatted as "DOMAIN\user", "DOMAIN/user"
                or "user@DOMAIN"
    :param spn: (optional) the full service principal name.
                Defaults to "krbtgt/<realm>"
    :param ip: the KDC ip. (optional. If not provided, Scapy will query the DNS for
               _kerberos._tcp.dc._msdcs.domain.local).
    :param target: the target IP/hostname entered by the user.
    :param kerberos_required: require kerberos
    :param password: (optional) otherwise, pass the user's password
    :param HashNt: (bytes) if provided, used for auth (NTLM)
    :param HashAes256Sha96: if provided, used for auth (Kerberos)
    :param HashAes128Sha96: if provided, used for auth (Kerberos)
    :param ccache: if provided, a path to a CCACHE (Kerberos). Else use KRB5CCNAME.
    :param x509: (optional) pass a x509 certificate for PKINIT.
    :param x509key: (optional) pass the private key of the x509 certificate for PKINIT.
    :param p12: (optional) use a pfx/p12 instead of x509 and x509key. In this case,
        'password' is the password of the p12.
    :param host: (optional) the host performing the AS-Req. WIN11 by default.
    """
    t = Ticketer()

    if ccache is None and "KRB5CCNAME" in os.environ:
        ccache = os.environ["KRB5CCNAME"]
    elif ccache is None:
        assert (
            False
        ), "'ccache' must be set, or the 'KRB5CCNAME' env var must be configured !"

    if pathlib.Path(ccache).exists():
        t.open_ccache(ccache)

    # Process key argument
    key = None
    if key is None and HashAes256Sha96:
        key = Key(
            EncryptionType.AES256_CTS_HMAC_SHA1_96,
            HashAes256Sha96,
        )
    elif key is None and HashAes128Sha96:
        key = Key(
            EncryptionType.AES128_CTS_HMAC_SHA1_96,
            HashAes128Sha96,
        )
    elif key is None and HashNt:
        key = Key(
            EncryptionType.RC4_HMAC,
            HashNt,
        )

    # Depending on the action, call the sub-call
    if action == TicketerCliAction.REQUEST_TGT:
        assert upn, "'upn' must be provided !"

        t.request_tgt(
            upn=upn,
            spn=spn,
            ip=ip,
            password=password,
            realm=realm,
            key=key,
            x509=x509,
            x509key=x509key,
            p12=p12,
            host=host,
            debug=debug,
        )
    elif action == TicketerCliAction.REQUEST_ST:
        assert i is not None, "'i' must be provided !"
        assert spn is not None, "'spn' must be provided !"

        t.request_st(
            i,
            spn=spn,
            ip=ip,
            password=password,
            realm=realm,
            renew=renew,
            for_user=for_user,
            armor_with=armor_with,
            s4u2proxy=s4u2proxy,
            host=host,
            debug=debug,
        )
    elif action == TicketerCliAction.SHOW:
        t.show()
    elif action == TicketerCliAction.REMOVE_KRB:
        t.remove_krb(i)

    # Save ccache
    t.save_ccache(fname=ccache)


def main():
    """
    Main entry point
    """
    from scapy.utils import AutoArgparse

    conf.exts.load("scapy-red")
    AutoArgparse(ticketercli)


# For autocompletion generation
AUTOCOMPLETE_GEN = ticketercli

if __name__ == "__main__":
    main()
