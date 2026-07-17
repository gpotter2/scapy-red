# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy RED
# See https://scapy.net/ for more information
# Copyright (C) github/Ebrix

r"""
Authenticate against a domain via a Kerberos AS-REQ.

Thin CLI wrapper around :func:`scapy.layers.kerberos.krb_as_req`. The
underlying scapy call already covers every Active Directory long-term
secret format; this module just bridges argparse-friendly ``bytes``
arguments to the :class:`~scapy.libs.rfc3961.Key` objects scapy expects,
so the following auth modes are all reachable from the command line:

  - cleartext password (``--password``)
  - DES_CBC_MD5 key (``--KeyDes``)
  - RC4_HMAC key, aka the NT hash (``--HashNt``)
  - AES128_CTS_HMAC_SHA1_96 key (``--HashAes128Sha96``)
  - AES256_CTS_HMAC_SHA1_96 key (``--HashAes256Sha96``)
  - PKINIT via a PFX / P12 bundle (``--pfx``; ``--password`` is the
    PFX passphrase)
  - PKINIT via a separate X509 certificate + private key
    (``--x509`` + ``--x509key``)

Pass no credential at all and scapy will send an AS-REQ with no
PA-ENC-TIMESTAMP — useful against accounts flagged
``DONT_REQUIRE_PREAUTH`` (AS-REP roast). scapy prompts for a password
interactively in that case; pipe ``/dev/null`` or pass any flag to
suppress the prompt.

Pass ``--ccache PATH`` to save the resulting TGT and session key in MIT
ccache format, ready to be picked up by ``kinit`` / ``klist`` / any
GSSAPI consumer via ``KRB5CCNAME=FILE:PATH``. Pass ``--ccache-default``
to write to the current user's default cache (``$KRB5CCNAME`` if set,
else ``/tmp/krb5cc_<uid>``).

Examples::

    # Password, save to the current user's default ccache
    scapy-kerbauth --upn Administrator@DOM.LOCAL --ip 192.168.1.44 \
                   --password Bonjour1 --ccache-default

    # NT hash (RC4_HMAC key)
    scapy-kerbauth --upn Administrator@DOM.LOCAL --ip 192.168.1.44 \
                   --HashNt 32ed87bdb5fdc5e9cba88547376818d4

    # PKINIT via a PFX / P12, save to a specific ccache file
    scapy-kerbauth --upn Administrator@DOM.LOCAL --ip 192.168.1.44 \
                   --pfx ./administrator.pfx --password Bonjour1 \
                   --ccache /tmp/admin.ccache
"""

import os

from scapy.config import conf
from scapy.libs.rfc3961 import EncryptionType, Key
from scapy.modules.ticketer import Ticketer


def _default_ccache_path() -> str:
    """
    Return the current user's default ccache path, matching MIT krb5
    conventions: ``$KRB5CCNAME`` (with any ``FILE:`` prefix stripped) if
    set, otherwise ``/tmp/krb5cc_<uid>``.
    """
    env = os.environ.get("KRB5CCNAME")
    if env:
        return env[5:] if env.startswith("FILE:") else env
    return f"/tmp/krb5cc_{os.getuid()}"


def kerbauth(
    upn: str,
    ip: str = None,
    password: str = None,
    HashNt: bytes = None,
    HashAes128Sha96: bytes = None,
    HashAes256Sha96: bytes = None,
    KeyDes: bytes = None,
    pfx: str = None,
    pfx_password: str = None,
    x509: str = None,
    x509key: str = None,
    spn: str = None,
    ca: str = None,
    verify_cert: bool = True,
    ccache: str = None,
    ccache_default: bool = False,
    debug: int = 0,
):
    r"""
    Authenticate against a domain via a Kerberos AS-REQ and print the
    resulting TGT session key on success.

    :param upn: the user principal name (``user@DOMAIN``, ``DOMAIN\user``
        or ``DOMAIN/user``)
    :param ip: the KDC IP (optional; resolved via DC locator otherwise)
    :param password: if provided, used for auth
    :param pfx_password: PFX/P12 passphrase (used only with ``--pfx``).
        Falls back to ``--password`` if not set.
    :param HashNt: if provided, used for auth (RC4_HMAC key / NT hash)
    :param HashAes128Sha96: if provided, used for auth
        (AES128_CTS_HMAC_SHA1_96 key)
    :param HashAes256Sha96: if provided, used for auth
        (AES256_CTS_HMAC_SHA1_96 key)
    :param KeyDes: if provided, used for auth (DES_CBC_MD5 key)
    :param pfx: path to a PFX / P12 bundle for PKINIT
    :param x509: path to a PEM X509 certificate for PKINIT
    :param x509key: path to the matching PEM private key
    :param spn: the SPN to request (default ``krbtgt/<realm>``)
    :param ca: path to a PEM bundle of the CA(s) that signed the KDC's
        certificate (PKINIT only). Required to validate the KDC's
        signature on the AS-REP unless ``--no-verify-cert`` is set.
    :param verify_cert: validate the KDC's certificate against ``--ca``
        (PKINIT only, on by default). Pass ``--no-verify-cert`` to
        disable — useful when you don't have the CA on hand.
    :param ccache: if set, save the TGT + session key to this MIT ccache
        file (compatible with ``kinit`` / ``klist`` / GSSAPI consumers
        via ``KRB5CCNAME=FILE:<path>``)
    :param ccache_default: if set, save to the current user's default
        ccache (``$KRB5CCNAME`` or ``/tmp/krb5cc_<uid>``)
    :param debug: scapy debug verbosity
    """
    # Convert one of the long-term hash bytes into a Key object.
    key = None
    if HashAes256Sha96:
        key = Key(EncryptionType.AES256_CTS_HMAC_SHA1_96, key=HashAes256Sha96)
    elif HashAes128Sha96:
        key = Key(EncryptionType.AES128_CTS_HMAC_SHA1_96, key=HashAes128Sha96)
    elif HashNt:
        key = Key(EncryptionType.RC4_HMAC, key=HashNt)
    elif KeyDes:
        key = Key(EncryptionType.DES_CBC_MD5, key=KeyDes)

    # ``Ticketer.request_tgt`` wraps ``krb_as_req`` and additionally
    # stores the (TGT, session key) pair in an in-memory CCache, which
    # we then optionally serialize to disk via ``save_ccache``.
    t = Ticketer()
    # scapy's ``krb_as_req`` overloads ``password`` to also mean the
    # PFX passphrase when ``p12`` is set; split that at the CLI layer so
    # ``--password`` is unambiguously the Kerberos password.
    t.request_tgt(
        upn=upn,
        spn=spn,
        ip=ip,
        key=key,
        password=(pfx_password or password) if pfx else password,
        p12=pfx,
        x509=x509,
        x509key=x509key,
        ca=ca,
        no_verify_cert=not verify_cert,
        debug=debug,
    )

    ct = conf.color_theme
    if not t.ccache.credentials:
        print(ct.red(f"[-] Authentication failed for {upn}"))
        return

    print(ct.green(f"[+] Authentication succeeded for {upn}"))
    t.show()

    if ccache or ccache_default:
        path = ccache or _default_ccache_path()
        t.save_ccache(path)
        print(ct.green(f"[+] Saved TGT to {path}"))
        print(f"    Use it with:  export KRB5CCNAME=FILE:{path}")


def main():
    """
    Main entry point
    """
    from scapy.utils import AutoArgparse

    conf.exts.load("scapy-red")
    AutoArgparse(kerbauth)


# For autocompletion generation
AUTOCOMPLETE_GEN = kerbauth

if __name__ == "__main__":
    main()
