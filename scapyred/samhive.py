# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy RED
# See https://scapy.net/ for more information
# Copyright (C) github/Ebrix

r"""
Remote SAM hive dumper.

This module talks to a remote Windows host through the Remote Registry
service (MS-RRP), reusing scapy-red's :class:`scapyred.winreg.RegClient`
for transport, and decodes every interesting field of the SAM hive
locally.

For every account we extract:

  - LM and NT hashes plus their full password history (decrypted)
  - the SAM_USER_V string slots (full name, comment, user comment, home
    directory, home drive, logon script, profile path, allowed
    workstations, weekly logon-hours bitmap)
  - the SAM_USER_F numeric / timestamp fields (UAC flags, primary
    group, last logon / last logoff / password last set / account
    expires / password can change, country code, code page,
    bad-password count and logon count)

We also extract:

  - the domain-level password & lockout policy from
    ``SAM\Domains\Account\F``: creation time, modified count,
    min/max password age, lockout policy, password complexity
    properties, server role, NextRid;
  - the local groups (aliases) from
    ``SAM\Domains\<Builtin|Account>\Aliases``: alias name, comment,
    member SIDs.

For LSA secrets from the SECURITY hive (machine account password & NT
hash, DPAPI_SYSTEM, NL$KM, service account credentials, etc.) see the
companion :mod:`scapyred.securityhive` module.

References
----------
The on-disk SAM layout is not officially documented by Microsoft; the
binary structures decoded here are reconstructed from a few public
sources, all of which are explicitly cited next to each structure in
the body of this file:

- ``SysKey and the SAM``, Brendan Dolan-Gavitt, 2008 — the BootKey
  scrambling and the legacy RC4-MD5 SAM_KEY_DATA / SAM_HASH layouts.
  http://moyix.blogspot.com/2008/02/syskey-and-sam.html
- ``impacket/examples/secretsdump.py`` (Fortra / SecureAuth) — the
  reference open-source implementation; covers both the legacy
  RC4-MD5 path and the modern AES-CBC path introduced with
  Windows 10 / Server 2016 (SAM_KEY_DATA_AES, SAM_HASH_AES).
  https://github.com/fortra/impacket
- ``Velocidex/regparser`` (Mike Cohen) — independent Go decoder of
  the same on-disk structures; useful as an offset cross-reference.
  https://github.com/Velocidex/regparser/blob/master/sam.go
- ``Cracking SAM Files Containing Stored Local Hashes``,
  Andreas Schuster, CRYPTLOG, 2002 — origin of the per-RID DES
  hash-wrap analysis.
- ``pwdump`` / Samba's ``smbpasswd`` — the canonical "str_to_key"
  routine used to expand a 7-byte string into a parity-corrected
  DES key.
- Microsoft Open Specifications, ``[MS-SAMR]`` §2.2.1 and §2.2.4 —
  the documented enums (``USER_ACCOUNT_*`` UAC bitmap, password
  properties, server role) carried in the otherwise undocumented
  on-disk structures.
- Microsoft Open Specifications, ``[MS-DTYP]`` §2.3.3 (FILETIME)
  and §2.4.2 (SID).

The exact field offsets used here have been re-validated against a
live Windows Server 2025 SAM hive.
"""

import hashlib
import logging
import struct
import sys

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# TripleDES has been relocated to ``decrepit`` in cryptography 43+; prefer
# that path when it is available so we don't ride the deprecation alarm.
try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import (
        TripleDES as _TripleDES,
    )
except ImportError:
    _TripleDES = algorithms.TripleDES

from scapy.config import conf
from scapy.error import log_runtime
from scapy.layers.windows.security import WINNT_SID
from scapy.themes import DefaultTheme, NoTheme

from scapyred.winreg import RegClient
from scapyred._winhive import (
    _banner,
    _i64,
    _read_value,
    _u16,
    _u32,
    _u64,
    get_boot_key,
)


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

# Magic strings used by the legacy RC4-MD5 SAM derivation — see moyix
# blog post above and impacket ``secretsdump.SAMHashes``.
_AQWERTY = b"!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0"
_ANUM = b"0123456789012345678901234567890123456789\0"
_NTPASSWORD = b"NTPASSWORD\0"
_LMPASSWORD = b"LMPASSWORD\0"

# Empty LM and NT hash placeholders, used when a slot contains no real
# hash so the pwdump output keeps the canonical sentinel values.
_EMPTY_LM = bytes.fromhex("aad3b435b51404eeaad3b435b51404ee")
_EMPTY_NT = bytes.fromhex("31d6cfe0d16ae931b73c59d7e0c089c0")

# UAC bitmap — see [MS-SAMR] §2.2.1.12.
_UAC_FLAGS = [
    (0x00000001, "ACCOUNT_DISABLED"),
    (0x00000002, "HOME_DIR_REQUIRED"),
    (0x00000004, "PASSWD_NOT_REQUIRED"),
    (0x00000008, "TEMP_DUPLICATE_ACCOUNT"),
    (0x00000010, "NORMAL_ACCOUNT"),
    (0x00000020, "MNS_LOGON_ACCOUNT"),
    (0x00000040, "INTERDOMAIN_TRUST_ACCOUNT"),
    (0x00000080, "WORKSTATION_TRUST_ACCOUNT"),
    (0x00000100, "SERVER_TRUST_ACCOUNT"),
    (0x00000200, "DONT_EXPIRE_PASSWORD"),
    (0x00000400, "ACCOUNT_AUTO_LOCKED"),
    (0x00000800, "ENCRYPTED_TEXT_PASSWORD_ALLOWED"),
    (0x00001000, "SMARTCARD_REQUIRED"),
    (0x00002000, "TRUSTED_FOR_DELEGATION"),
    (0x00004000, "NOT_DELEGATED"),
    (0x00008000, "USE_DES_KEY_ONLY"),
    (0x00010000, "DONT_REQUIRE_PREAUTH"),
    (0x00020000, "PASSWORD_EXPIRED"),
    (0x00040000, "TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION"),
    (0x00080000, "NO_AUTH_DATA_REQUIRED"),
    (0x00100000, "PARTIAL_SECRETS_ACCOUNT"),
    (0x00200000, "USE_AES_KEYS"),
]

# UAC flags worth flagging in yellow when reviewing privileges.
_UAC_FLAGS_HOT = frozenset(
    {
        "PASSWD_NOT_REQUIRED",
        "DONT_EXPIRE_PASSWORD",
        "PASSWORD_EXPIRED",
        "DONT_REQUIRE_PREAUTH",
        "TRUSTED_FOR_DELEGATION",
        "TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION",
        "USE_DES_KEY_ONLY",
    }
)

# DOMAIN_PASSWORD_INFORMATION.PasswordProperties — see [MS-SAMR] §2.2.1.1.
_PWD_PROPERTIES = [
    (0x00000001, "DOMAIN_PASSWORD_COMPLEX"),
    (0x00000002, "DOMAIN_PASSWORD_NO_ANON_CHANGE"),
    (0x00000004, "DOMAIN_PASSWORD_NO_CLEAR_CHANGE"),
    (0x00000008, "DOMAIN_LOCKOUT_ADMINS"),
    (0x00000010, "DOMAIN_PASSWORD_STORE_CLEARTEXT"),
    (0x00000020, "DOMAIN_REFUSE_PASSWORD_CHANGE"),
]

# DOMAIN_SERVER_ROLE — see [MS-SAMR] §2.2.4.16.
_SERVER_ROLES = {
    0: "DomainServerRoleStandalone",
    1: "DomainServerRoleMember",
    2: "DomainServerRoleBackup",
    3: "DomainServerRolePrimary",
}


# --------------------------------------------------------------------------- #
# Crypto helpers
# --------------------------------------------------------------------------- #


def _des_set_odd_parity(seven: bytes) -> bytes:
    """
    Expand a 7-byte string into the 8-byte DES key produced by Windows
    when generating per-RID DES keys (the classic ``str_to_key`` routine).
    See Samba's ``smbpasswd`` documentation and the ``pwdump`` source
    code.
    """
    k = bytearray(8)
    k[0] = seven[0] >> 1
    k[1] = ((seven[0] & 0x01) << 6) | (seven[1] >> 2)
    k[2] = ((seven[1] & 0x03) << 5) | (seven[2] >> 3)
    k[3] = ((seven[2] & 0x07) << 4) | (seven[3] >> 4)
    k[4] = ((seven[3] & 0x0F) << 3) | (seven[4] >> 5)
    k[5] = ((seven[4] & 0x1F) << 2) | (seven[5] >> 6)
    k[6] = ((seven[5] & 0x3F) << 1) | (seven[6] >> 7)
    k[7] = seven[6] & 0x7F
    for i in range(8):
        k[i] = (k[i] << 1) & 0xFF
    return bytes(k)


def _des(key8: bytes, data8: bytes, decrypt: bool = True) -> bytes:
    """
    Single-DES on one block. ``cryptography`` does not expose plain DES,
    so we drive it through TripleDES with K1=K2=K3 — passing the 8-byte
    DES key three times yields plain DES.
    """
    cipher = Cipher(_TripleDES(key8 * 3), modes.ECB())
    op = cipher.decryptor() if decrypt else cipher.encryptor()
    return op.update(data8) + op.finalize()


def _rid_des_keys(rid: int) -> tuple[bytes, bytes]:
    """
    Derive the two 8-byte DES keys used to wrap an LM/NT hash for a
    given account RID. See Schuster (2002) and impacket's
    ``secretsdump.SAMHashes._removeRID`` for the canonical algorithm.
    """
    r = struct.pack("<L", rid)
    s1 = bytes((r[0], r[1], r[2], r[3], r[0], r[1], r[2]))
    s2 = bytes((r[3], r[0], r[1], r[2], r[3], r[0], r[1]))
    return _des_set_odd_parity(s1), _des_set_odd_parity(s2)


def _rid_unwrap(double_des_blob: bytes, rid: int) -> bytes:
    """
    Reverse the per-RID DES wrapping that Windows applies on top of
    every LM/NT hash before storing it in the SAM hive.
    """
    k1, k2 = _rid_des_keys(rid)
    return _des(k1, double_des_blob[:8]) + _des(k2, double_des_blob[8:16])


def _arc4(key: bytes, data: bytes) -> bytes:
    """RC4 one-shot — used by the legacy SAM key derivation."""
    cipher = Cipher(algorithms.ARC4(key), mode=None)
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()


def _aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """AES-CBC decrypt without padding — SAM stores raw 16-byte blocks."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec = cipher.decryptor()
    return dec.update(data) + dec.finalize()


# --------------------------------------------------------------------------- #
# Time / flag formatting
# --------------------------------------------------------------------------- #


def _filetime_to_iso(ft: int) -> str:
    """
    Convert a Windows FILETIME (100ns since 1601-01-01, see [MS-DTYP]
    §2.3.3) to an ISO 8601 string, or one of the well-known sentinel
    tags (``0`` for 'never set' and ``0x7FFFFFFFFFFFFFFF`` for 'never').
    """
    if ft == 0:
        return "(never set)"
    if ft == 0x7FFFFFFFFFFFFFFF:
        return "(never)"
    seconds = (ft - 116444736000000000) // 10000000
    if seconds < 0:
        return f"raw=0x{ft:016x}"
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return f"raw=0x{ft:016x}"


def _filetime_interval(ft: int) -> str:
    """
    Render a FILETIME-encoded duration (e.g. MaxPasswordAge,
    LockoutDuration). [MS-SAMR] stores active durations as negative
    100ns ticks; ``-0x8000000000000000`` is the conventional 'never
    expire' sentinel.
    """
    if ft == 0:
        return "0"
    if ft == -0x8000000000000000:
        return "(never)"
    secs = abs(ft) / 10_000_000
    if secs >= 86400:
        return f"{secs / 86400:.2f} days"
    if secs >= 3600:
        return f"{secs / 3600:.2f} hours"
    if secs >= 60:
        return f"{secs / 60:.2f} minutes"
    return f"{secs:.0f} seconds"


def _decode_flags(value: int, table: list) -> str:
    """Render a bitmap as ``0xHEX (FLAG1|FLAG2)`` using ``table``."""
    names = [name for mask, name in table if value & mask]
    if not names:
        return f"0x{value:x}"
    return f"0x{value:x} ({'|'.join(names)})"


def _decode_uac_colored(value: int) -> str:
    """
    Like :func:`_decode_flags` for the UAC bitmap, but colorize the
    less-interesting flags (gray for disabled / locked) and the
    privilege-relevant ones (yellow). When ``conf.color_theme`` is the
    no-op theme this still produces clean plain text.
    """
    ct = conf.color_theme
    parts = []
    for mask, name in _UAC_FLAGS:
        if not value & mask:
            continue
        if name == "ACCOUNT_DISABLED" or name == "ACCOUNT_AUTO_LOCKED":
            parts.append(ct.gray(name))
        elif name in _UAC_FLAGS_HOT:
            parts.append(ct.yellow(name))
        else:
            parts.append(name)
    if not parts:
        return f"0x{value:x}"
    return f"0x{value:x} ({'|'.join(parts)})"


# --------------------------------------------------------------------------- #
# Hashed BootKey (SAM_KEY_DATA / SAM_KEY_DATA_AES)
# --------------------------------------------------------------------------- #
#
# The 16-byte "hashed BootKey" is encrypted at the start of Key0 in
# ``SAM\Domains\Account\F``. Two on-disk formats coexist:
#
# Legacy (Revision 1) — RC4-MD5, see moyix's blog post::
#
#   struct SAM_KEY_DATA {
#       BYTE  Revision;          // 0x01
#       BYTE  Unknown[3];
#       DWORD Length;
#       BYTE  Salt[16];
#       BYTE  Key[16];
#       BYTE  CheckSum[16];
#       DWORD Reserved[2];
#   }
#
# Modern (Revision 2/3) — AES-CBC, introduced with Windows 10 / Server
# 2016, see impacket ``secretsdump.SAM_KEY_DATA_AES``::
#
#   struct SAM_KEY_DATA_AES {
#       BYTE  Revision;          // 0x02 or 0x03
#       BYTE  Unknown[3];
#       DWORD Length;
#       DWORD CheckSumLen;
#       DWORD DataLen;
#       BYTE  Salt[16];          // also the IV
#       BYTE  Data[DataLen];     // first 16 plaintext bytes = hashed BK
#   }


def derive_hashed_bootkey(f_value: bytes, boot_key: bytes) -> bytes:
    """
    Decrypt the 16-byte "hashed BootKey" embedded in the F value of
    ``SAM\\Domains\\Account``. Supports both the legacy RC4-MD5 layout
    (Revision == 1) and the modern AES-CBC layout (Revision == 2 or 3).
    """
    # Key0 starts at offset 0x68 in SAM_DOMAIN_ACCOUNT_F (right after
    # the policy header).
    key0 = f_value[0x68:]
    revision = key0[0]

    if revision in (0x02, 0x03):
        data_len = _u32(key0, 0x0C)
        salt = key0[0x10:0x20]
        data = key0[0x20 : 0x20 + data_len]
        return _aes_cbc_decrypt(boot_key, salt, data)[:16]

    if revision == 0x01:
        salt = key0[0x08:0x18]
        key = key0[0x18:0x28]
        checksum = key0[0x28:0x38]
        rc4_key = hashlib.md5(salt + _AQWERTY + boot_key + _ANUM).digest()
        decrypted = _arc4(rc4_key, key + checksum)
        hashed_bk = decrypted[:16]
        expected = hashlib.md5(hashed_bk + _ANUM + _AQWERTY + hashed_bk).digest()
        if expected != decrypted[16:32]:
            log_runtime.warning(
                "Hashed BootKey checksum mismatch - decryption may be wrong"
            )
        return hashed_bk

    raise RuntimeError(f"Unsupported SAM_KEY_DATA revision: {revision:#x}")


# --------------------------------------------------------------------------- #
# Hash & history decryption (SAM_HASH / SAM_HASH_AES)
# --------------------------------------------------------------------------- #
#
# Each on-disk LM or NT hash slot is wrapped twice:
#
#   1. an outer cipher (RC4-MD5 or AES-CBC) keyed off the hashed
#      BootKey, the account RID and a per-slot constant
#      (``NTPASSWORD\0`` / ``LMPASSWORD\0``);
#   2. an inner per-RID double-DES wrap (Schuster 2002).
#
# SAM_HASH (Revision 1, RC4-MD5)::
#
#   struct SAM_HASH {
#       WORD  PekId;
#       WORD  Revision;          // 0x0001
#       BYTE  Hash[16];          // RC4-encrypted, RID-DES-wrapped
#   };
#
# SAM_HASH_AES (Revision 2, AES-CBC, Win10+)::
#
#   struct SAM_HASH_AES {
#       WORD  PekId;
#       WORD  Revision;          // 0x0002
#       DWORD DataOffset;
#       BYTE  Salt[16];          // = AES IV
#       BYTE  Data[N*16];        // AES-CBC, RID-DES-wrapped per block
#   };
#
# The same two layouts are reused for password history slots — they
# simply contain N concatenated 16-byte plaintext blocks instead of
# one. References: impacket ``secretsdump.SAM_HASH`` /
# ``SAM_HASH_AES``.


def _decrypt_hash_slot(
    enc_blob: bytes,
    hashed_bk: bytes,
    rid: int,
    password_const: bytes,
) -> list[bytes]:
    """
    Decrypt one SAM hash slot (single hash *or* password history) and
    return the list of bare 16-byte LM/NT hashes it contained.

    :param enc_blob: the raw V slot content.
    :param hashed_bk: the 16-byte hashed BootKey.
    :param rid: the account RID — used both for the RC4 key derivation
                and for the per-RID DES unwrap.
    :param password_const: ``_NTPASSWORD`` for an NT hash slot,
                           ``_LMPASSWORD`` for an LM hash slot.
    """
    if not enc_blob:
        return []
    revision = _u16(enc_blob, 2)
    if revision == 0x01:
        if len(enc_blob) < 4:
            return []
        rc4_key = hashlib.md5(
            hashed_bk + struct.pack("<L", rid) + password_const
        ).digest()
        plain = _arc4(rc4_key, enc_blob[4:])
    elif revision == 0x02:
        if len(enc_blob) < 24:
            return []
        salt = enc_blob[8:24]
        ct = enc_blob[24:]
        ct = ct[: len(ct) - (len(ct) % 16)]
        if not ct:
            return []
        plain = _aes_cbc_decrypt(hashed_bk, salt, ct)
    else:
        log_runtime.warning("Unknown SAM hash revision %#x", revision)
        return []

    return [_rid_unwrap(plain[i : i + 16], rid) for i in range(0, len(plain) - 15, 16)]


# --------------------------------------------------------------------------- #
# USER_ACCOUNT_V parsing
# --------------------------------------------------------------------------- #
#
# Found at ``SAM\Domains\Account\Users\<RID>\V``. Header is a fixed
# table of 16 (offset, length, unknown) triplets — 12 bytes each — and
# the data section starts at 0xCC. Every offset is relative to that
# data base.
#
# Slot map (verified on a live Windows Server 2025, cross-checked
# against impacket ``secretsdump.USER_ACCOUNT_V`` and Velocidex
# ``regparser/sam.go``)::
#
#   0x0C  Name                  0x84  HoursAllowed
#   0x18  FullName              0x90  (unknown / 8-byte payload)
#   0x24  Comment               0x9C  LMHash         (SAM_HASH[_AES])
#   0x30  UserComment           0xA8  NTHash         (SAM_HASH[_AES])
#   0x3C  HomeDir               0xB4  NTPwHistory    (SAM_HASH[_AES])
#   0x48  HomeDirDrive          0xC0  LMPwHistory    (SAM_HASH[_AES])
#   0x54  ScriptPath
#   0x60  ProfilePath
#   0x6C  Workstations
#   0x78  (unknown)

_V_DATA_BASE = 0xCC


@dataclass
class _UserV:
    """Strings + raw hash slots extracted from a USER_ACCOUNT_V buffer."""

    name: str = ""
    full_name: str = ""
    comment: str = ""
    user_comment: str = ""
    home_dir: str = ""
    home_dir_drive: str = ""
    script_path: str = ""
    profile_path: str = ""
    workstations: str = ""
    logon_hours: bytes = b""
    enc_lm: bytes = b""
    enc_nt: bytes = b""
    enc_nt_history: bytes = b""
    enc_lm_history: bytes = b""


def _v_slice(v: bytes, slot_off: int) -> bytes:
    """Return the data section bytes pointed to by the (offset, length)
    pair stored at ``v[slot_off : slot_off+8]``."""
    off = _u32(v, slot_off)
    ln = _u32(v, slot_off + 4)
    if not ln:
        return b""
    return v[_V_DATA_BASE + off : _V_DATA_BASE + off + ln]


def _v_str(v: bytes, slot_off: int) -> str:
    """UTF-16-LE decode of the slot pointed to by ``slot_off``."""
    return _v_slice(v, slot_off).decode("utf-16-le", errors="replace")


def _parse_user_v(v: bytes) -> _UserV:
    """Decode every interesting slot of a USER_ACCOUNT_V buffer."""
    return _UserV(
        name=_v_str(v, 0x0C),
        full_name=_v_str(v, 0x18),
        comment=_v_str(v, 0x24),
        user_comment=_v_str(v, 0x30),
        home_dir=_v_str(v, 0x3C),
        home_dir_drive=_v_str(v, 0x48),
        script_path=_v_str(v, 0x54),
        profile_path=_v_str(v, 0x60),
        workstations=_v_str(v, 0x6C),
        logon_hours=_v_slice(v, 0x84),
        enc_lm=_v_slice(v, 0x9C),
        enc_nt=_v_slice(v, 0xA8),
        enc_nt_history=_v_slice(v, 0xB4),
        enc_lm_history=_v_slice(v, 0xC0),
    )


# --------------------------------------------------------------------------- #
# USER_ACCOUNT_F parsing
# --------------------------------------------------------------------------- #
#
# Found at ``SAM\Domains\Account\Users\<RID>\F``. 80-byte fixed-size
# blob (verified against live data and against impacket
# ``secretsdump.USER_ACCOUNT_F``)::
#
#   0x00  Revision (u16) + 6 unknown bytes
#   0x08  LastLogon            (FILETIME)
#   0x10  LastLogoff           (FILETIME)
#   0x18  PasswordLastSet      (FILETIME)
#   0x20  AccountExpires       (FILETIME)
#   0x28  PasswordCanChange    (FILETIME)
#   0x30  Rid                  (u32)
#   0x34  PrimaryGroupId       (u32)
#   0x38  UserAccountControl   (u32)         see [MS-SAMR] §2.2.1.12
#   0x3C  unknown (8 bytes)
#   0x44  unknown (4 bytes)
#   0x48  CountryCode          (u16)
#   0x4A  CodePage             (u16)
#   0x4C  BadPasswordCount     (u16)
#   0x4E  LogonCount           (u16)


@dataclass
class _UserF:
    """Numeric / timestamp fields extracted from a USER_ACCOUNT_F buffer."""

    last_logon: int = 0
    last_logoff: int = 0
    password_last_set: int = 0
    account_expires: int = 0
    password_can_change: int = 0
    rid: int = 0
    primary_group: int = 0
    user_account_control: int = 0
    country_code: int = 0
    code_page: int = 0
    bad_password_count: int = 0
    logon_count: int = 0


def _parse_user_f(f: bytes) -> _UserF:
    """Decode the 80-byte USER_ACCOUNT_F buffer."""
    return _UserF(
        last_logon=_u64(f, 0x08),
        last_logoff=_u64(f, 0x10),
        password_last_set=_u64(f, 0x18),
        account_expires=_u64(f, 0x20),
        password_can_change=_u64(f, 0x28),
        rid=_u32(f, 0x30),
        primary_group=_u32(f, 0x34),
        user_account_control=_u32(f, 0x38),
        country_code=_u16(f, 0x48),
        code_page=_u16(f, 0x4A),
        bad_password_count=_u16(f, 0x4C),
        logon_count=_u16(f, 0x4E),
    )


# --------------------------------------------------------------------------- #
# DOMAIN_ACCOUNT_F parsing
# --------------------------------------------------------------------------- #
#
# Found at ``SAM\Domains\Account\F``. Holds the password / lockout
# policy followed by the SAM_KEY_DATA[_AES] starting at offset 0x68
# (decoded by :func:`derive_hashed_bootkey`).
#
# Header layout (verified live, cross-checked against impacket
# ``secretsdump.DOMAIN_ACCOUNT_F``)::
#
#   0x00  Revision (u16) + Unknown1 (u16)
#   0x04  unknown                            (u32)
#   0x08  CreationTime                       (FILETIME)
#   0x10  DomainModifiedCount                (u64)
#   0x18  MaxPasswordAge                     (signed FILETIME interval)
#   0x20  MinPasswordAge                     (signed FILETIME interval)
#   0x28  ForceLogoff                        (signed FILETIME interval)
#   0x30  LockoutDuration                    (signed FILETIME interval)
#   0x38  LockoutObservationWindow           (signed FILETIME interval)
#   0x40  ModifiedCountAtLastPromotion       (u64)
#   0x48  NextRid                            (u32)
#   0x4C  PasswordProperties                 (u32)  [MS-SAMR] §2.2.1.1
#   0x50  MinPasswordLength                  (u16)
#   0x52  PasswordHistoryLength              (u16)
#   0x54  LockoutThreshold                   (u16)
#   0x56  unknown                            (u16)
#   0x58  ServerState                        (u32)
#   0x5C  ServerRole                         (u16)  [MS-SAMR] §2.2.4.16
#   0x5E  UasCompatibilityRequired           (u16)


@dataclass
class SamDomainPolicy:
    """Password & lockout policy parsed from SAM_DOMAIN_ACCOUNT_F."""

    creation_time: int = 0
    domain_modified_count: int = 0
    max_password_age: int = 0
    min_password_age: int = 0
    force_logoff: int = 0
    lockout_duration: int = 0
    lockout_observation_window: int = 0
    modified_count_at_last_promotion: int = 0
    next_rid: int = 0
    password_properties: int = 0
    min_password_length: int = 0
    password_history_length: int = 0
    lockout_threshold: int = 0
    server_state: int = 0
    server_role: int = 0
    uas_compatibility_required: int = 0


def _parse_domain_f(f: bytes) -> SamDomainPolicy:
    """Decode the policy header of SAM_DOMAIN_ACCOUNT_F."""
    return SamDomainPolicy(
        creation_time=_u64(f, 0x08),
        domain_modified_count=_u64(f, 0x10),
        max_password_age=_i64(f, 0x18),
        min_password_age=_i64(f, 0x20),
        force_logoff=_i64(f, 0x28),
        lockout_duration=_i64(f, 0x30),
        lockout_observation_window=_i64(f, 0x38),
        modified_count_at_last_promotion=_u64(f, 0x40),
        next_rid=_u32(f, 0x48),
        password_properties=_u32(f, 0x4C),
        min_password_length=_u16(f, 0x50),
        password_history_length=_u16(f, 0x52),
        lockout_threshold=_u16(f, 0x54),
        server_state=_u32(f, 0x58),
        server_role=_u16(f, 0x5C),
        uas_compatibility_required=_u16(f, 0x5E),
    )


# --------------------------------------------------------------------------- #
# DOMAIN_ALIAS_C parsing (local groups)
# --------------------------------------------------------------------------- #
#
# Each alias key under
# ``SAM\Domains\<Builtin|Account>\Aliases\<HexAliasRID>`` carries a
# single ``C`` value with the layout below. Member SIDs are stored
# verbatim (raw WINNT_SID byte structures, see [MS-DTYP] §2.4.2),
# concatenated. Reference: impacket ``secretsdump`` and Velocidex's
# regparser; offsets re-validated against the BUILTIN\\Administrators
# alias on a live Windows Server 2025 host.
#
#   0x00  AliasId               (u32)   matches the registry key name
#   0x04  unknown               (u32)
#   0x08  unknown               (u32)   often equals NameOffset
#   0x0C  Revision              (u32)   typically 0x00010003
#   0x10  NameOffset            (u32)   relative to the data section at 0x34
#   0x14  NameLength            (u32)   bytes (UTF-16 LE)
#   0x18  unknown               (u32)
#   0x1C  CommentOffset         (u32)
#   0x20  CommentLength         (u32)
#   0x24  unknown               (u32)
#   0x28  MembersOffset         (u32)
#   0x2C  MembersLength         (u32)
#   0x30  NumberOfMembers       (u32)
#   0x34: data section: SecurityDescriptor, then Name, then Comment,
#         then a packed run of NumberOfMembers WINNT_SID byte structs.

_ALIAS_DATA_BASE = 0x34


@dataclass
class SamAlias:
    r"""A local group ('alias') read out of SAM\Domains\<dom>\Aliases."""

    # "Builtin" or "Account"
    domain: str

    # Alias RID — e.g. 0x220 (544) for BUILTIN\Administrators.
    alias_id: int

    # Display name and comment (UTF-16 strings).
    name: str
    comment: str

    # Member SIDs as canonical "S-..." strings.
    members: list[str] = field(default_factory=list)


def _parse_sids(buf: bytes, count: int) -> list[str]:
    """
    Walk a buffer of concatenated raw WINNT_SID byte structures and
    return each SID's canonical ``S-...`` string. SIDs are
    variable-size (8 + SubAuthCount*4 bytes) so we re-parse the size
    from each header rather than relying on a stride.
    """
    sids: list[str] = []
    p = 0
    for _ in range(count):
        if p + 8 > len(buf):
            break
        sub_auth_count = buf[p + 1]
        size = 8 + sub_auth_count * 4
        if p + size > len(buf):
            break
        try:
            sids.append(WINNT_SID(buf[p : p + size]).summary())
        except Exception:
            sids.append(buf[p : p + size].hex())
        p += size
    return sids


def _parse_alias_c(domain: str, fallback_rid: int, c: bytes) -> SamAlias:
    """Decode one DOMAIN_ALIAS_C buffer into a :class:`SamAlias`."""
    base = _ALIAS_DATA_BASE
    name_off = _u32(c, 0x10)
    name_len = _u32(c, 0x14)
    comment_off = _u32(c, 0x1C)
    comment_len = _u32(c, 0x20)
    members_off = _u32(c, 0x28)
    members_len = _u32(c, 0x2C)
    num_members = _u32(c, 0x30)
    return SamAlias(
        domain=domain,
        alias_id=_u32(c, 0x00) or fallback_rid,
        name=c[base + name_off : base + name_off + name_len].decode(
            "utf-16-le", errors="replace"
        ),
        comment=c[base + comment_off : base + comment_off + comment_len].decode(
            "utf-16-le", errors="replace"
        ),
        members=_parse_sids(
            c[base + members_off : base + members_off + members_len],
            num_members,
        ),
    )


def dump_aliases(client: RegClient) -> list[SamAlias]:
    r"""
    Enumerate local groups under both the Builtin and Account domains
    of the SAM hive (``SAM\Domains\Builtin\Aliases`` and
    ``SAM\Domains\Account\Aliases``) and return the list of aliases.
    """
    out: list[SamAlias] = []
    for domain in ("Builtin", "Account"):
        base = f"SAM\\SAM\\Domains\\{domain}\\Aliases"
        try:
            entries = client.ls(base)
        except Exception as exc:
            log_runtime.debug("No aliases under %s: %s", base, exc)
            continue
        for name in entries:
            # Per-alias keys are 8-hex-char strings; skip "Members" / "Names".
            if len(name) != 8:
                continue
            try:
                alias_rid = int(name, 16)
            except ValueError:
                continue
            try:
                cval = _read_value(client, f"{base}\\{name}", "C")
            except RuntimeError as exc:
                log_runtime.warning("alias %s\\%s: %s", domain, name, exc)
                continue
            try:
                out.append(_parse_alias_c(domain, alias_rid, cval))
            except (struct.error, IndexError) as exc:
                log_runtime.warning("alias %s\\%s: parse error: %s", domain, name, exc)
                continue
    return out


def _get_machine_sid(client: RegClient) -> str:
    r"""
    Locate the machine domain SID (``S-1-5-21-X-Y-Z``) embedded in
    ``SAM\Domains\Account\V``. The V buffer ends with the machine SID
    in raw form — there is no published structure documenting its
    exact offset, so we search for the canonical 12-byte prefix
    ``\x01\x04 \x00\x00\x00\x00\x00\x05 \x15\x00\x00\x00`` (Revision=1,
    SubAuthCount=4, NT-Authority, sub[0]=21).
    """
    try:
        v = _read_value(client, "SAM\\SAM\\Domains\\Account", "V")
    except RuntimeError:
        return ""
    needle = b"\x01\x04\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00"
    pos = v.rfind(needle)
    if pos < 0 or pos + 24 > len(v):
        return ""
    try:
        return WINNT_SID(v[pos : pos + 24]).summary()
    except Exception:
        return ""


# --------------------------------------------------------------------------- #
# Public account dataclass
# --------------------------------------------------------------------------- #


@dataclass
class SamUser:
    """One SAM account, with every field cross-decoded from V and F."""

    # RID and account name (from F.Rid and V.Name respectively).
    rid: int
    username: str

    # USER_V string slots.
    full_name: str = ""
    comment: str = ""
    user_comment: str = ""
    home_dir: str = ""
    home_dir_drive: str = ""
    script_path: str = ""
    profile_path: str = ""
    workstations: str = ""

    # Weekly logon-hours bitmap (typically 21 bytes = 168 bits).
    logon_hours: bytes = b""

    # USER_F numeric / timestamp fields.
    last_logon: int = 0
    last_logoff: int = 0
    password_last_set: int = 0
    account_expires: int = 0
    password_can_change: int = 0
    user_account_control: int = 0
    primary_group: int = 0
    country_code: int = 0
    code_page: int = 0
    bad_password_count: int = 0
    logon_count: int = 0

    # Decrypted hashes & password history.
    lm_hash: bytes = b""
    nt_hash: bytes = b""
    nt_history: list[bytes] = field(default_factory=list)
    lm_history: list[bytes] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# User dump
# --------------------------------------------------------------------------- #


def dump_users(client: RegClient, hashed_bk: bytes) -> list[SamUser]:
    r"""
    Walk ``SAM\Domains\Account\Users\<RID>`` and decode V & F for each
    user, then decrypt the LM/NT hashes and password history with the
    supplied 16-byte hashed BootKey.
    """
    users: list[SamUser] = []
    base = "SAM\\SAM\\Domains\\Account\\Users"
    for name in client.ls(base):
        # Per-user keys are 8-hex-char strings ("000001F4" etc.); skip
        # the "Names" container and any other non-RID entry.
        if len(name) != 8:
            continue
        try:
            rid = int(name, 16)
        except ValueError:
            continue
        ukey = f"{base}\\{name}"
        try:
            v_blob = _read_value(client, ukey, "V")
            f_blob = _read_value(client, ukey, "F")
        except RuntimeError as exc:
            log_runtime.warning("RID %s: %s", name, exc)
            continue
        try:
            v = _parse_user_v(v_blob)
            f = _parse_user_f(f_blob)
        except (struct.error, IndexError) as exc:
            log_runtime.warning("RID %s: parse error: %s", name, exc)
            continue

        lm_list = _decrypt_hash_slot(v.enc_lm, hashed_bk, rid, _LMPASSWORD)
        nt_list = _decrypt_hash_slot(v.enc_nt, hashed_bk, rid, _NTPASSWORD)
        lm_hist = _decrypt_hash_slot(v.enc_lm_history, hashed_bk, rid, _LMPASSWORD)
        nt_hist = _decrypt_hash_slot(v.enc_nt_history, hashed_bk, rid, _NTPASSWORD)

        users.append(
            SamUser(
                rid=rid,
                username=v.name,
                full_name=v.full_name,
                comment=v.comment,
                user_comment=v.user_comment,
                home_dir=v.home_dir,
                home_dir_drive=v.home_dir_drive,
                script_path=v.script_path,
                profile_path=v.profile_path,
                workstations=v.workstations,
                logon_hours=v.logon_hours,
                last_logon=f.last_logon,
                last_logoff=f.last_logoff,
                password_last_set=f.password_last_set,
                account_expires=f.account_expires,
                password_can_change=f.password_can_change,
                user_account_control=f.user_account_control,
                primary_group=f.primary_group,
                country_code=f.country_code,
                code_page=f.code_page,
                bad_password_count=f.bad_password_count,
                logon_count=f.logon_count,
                lm_hash=lm_list[0] if lm_list else _EMPTY_LM,
                nt_hash=nt_list[0] if nt_list else _EMPTY_NT,
                nt_history=nt_hist,
                lm_history=lm_hist,
            )
        )
    return users


# --------------------------------------------------------------------------- #
# Output rendering
# --------------------------------------------------------------------------- #


def _print_domain(policy: SamDomainPolicy) -> None:
    """Render the domain-level password / lockout policy."""
    _banner("Domain policy (SAM\\Domains\\Account\\F)")
    role = _SERVER_ROLES.get(policy.server_role, str(policy.server_role))
    print(
        f"  Creation time              : " f"{_filetime_to_iso(policy.creation_time)}"
    )
    print(f"  Domain modified count      : {policy.domain_modified_count}")
    print(
        f"  Min password age           : "
        f"{_filetime_interval(policy.min_password_age)}"
    )
    print(
        f"  Max password age           : "
        f"{_filetime_interval(policy.max_password_age)}"
    )
    print(
        f"  Force logoff               : " f"{_filetime_interval(policy.force_logoff)}"
    )
    print(
        f"  Lockout duration           : "
        f"{_filetime_interval(policy.lockout_duration)}"
    )
    print(
        f"  Lockout observation window : "
        f"{_filetime_interval(policy.lockout_observation_window)}"
    )
    print(f"  Lockout threshold          : {policy.lockout_threshold}")
    print(f"  Min password length        : {policy.min_password_length}")
    print(f"  Password history length    : {policy.password_history_length}")
    print(
        f"  Password properties        : "
        f"{_decode_flags(policy.password_properties, _PWD_PROPERTIES)}"
    )
    print(f"  Server role                : {role}")
    print(f"  Server state               : 0x{policy.server_state:x}")
    print(f"  Next RID                   : {policy.next_rid}")
    print()


def _print_user(
    u: SamUser,
    admin_rids: set,
    rid_to_groups: dict,
) -> None:
    """Render one SamUser block, with admin / disabled highlights and
    inline local-group membership."""
    ct = conf.color_theme
    is_admin = u.rid in admin_rids
    is_disabled = bool(u.user_account_control & 0x1)

    title = f"User: {u.username}  (RID {u.rid})"
    if is_admin:
        title = ct.red(ct.bold(title)) + " " + ct.red(ct.bold("[ADMIN]"))
    elif is_disabled:
        title = ct.gray(title) + " " + ct.gray("[disabled]")
    else:
        title = ct.bold(title)

    print(ct.cyan("=" * 64))
    print(title)
    print(ct.cyan("=" * 64))
    if u.full_name:
        print(f"  Full name             : {u.full_name}")
    if u.comment:
        print(f"  Comment               : {u.comment}")
    if u.user_comment:
        print(f"  User comment          : {u.user_comment}")
    if u.home_dir:
        print(f"  Home directory        : {u.home_dir}")
    if u.home_dir_drive:
        print(f"  Home drive            : {u.home_dir_drive}")
    if u.script_path:
        print(f"  Logon script          : {u.script_path}")
    if u.profile_path:
        print(f"  Profile path          : {u.profile_path}")
    if u.workstations:
        print(f"  Workstations          : {u.workstations}")
    print(
        f"  UAC                   : " f"{_decode_uac_colored(u.user_account_control)}"
    )
    print(f"  Primary group         : {u.primary_group}")
    print(f"  Country / code page   : {u.country_code} / {u.code_page}")
    print(f"  Bad password count    : {u.bad_password_count}")
    print(f"  Logon count           : {u.logon_count}")
    print(f"  Last logon            : {_filetime_to_iso(u.last_logon)}")
    print(f"  Last logoff           : {_filetime_to_iso(u.last_logoff)}")
    print(f"  Password last set     : " f"{_filetime_to_iso(u.password_last_set)}")
    print(f"  Account expires       : {_filetime_to_iso(u.account_expires)}")
    print(f"  Password can change   : " f"{_filetime_to_iso(u.password_can_change)}")
    if u.logon_hours:
        if u.logon_hours == b"\xff" * len(u.logon_hours):
            hours = "(any)"
        else:
            hours = u.logon_hours.hex()
        print(f"  Logon hours           : {hours}")
    groups = rid_to_groups.get(u.rid, [])
    if groups:
        line = ", ".join(groups)
        if is_admin:
            line = ct.red(ct.bold(line))
        print(f"  Member of             : {line}")
    nt_hex = u.nt_hash.hex()
    nt_disp = (
        ct.yellow(nt_hex + "  (= empty/no password)")
        if u.nt_hash == _EMPTY_NT
        else ct.bold(nt_hex) if is_admin else nt_hex
    )
    print(f"  LM hash               : {u.lm_hash.hex()}")
    print(f"  NT hash               : {nt_disp}")
    if u.nt_history:
        print(f"  NT history ({len(u.nt_history)} entries):")
        for i, h in enumerate(u.nt_history):
            print(f"    [{i:>2}] {h.hex()}")
    if u.lm_history:
        print(f"  LM history ({len(u.lm_history)} entries):")
        for i, h in enumerate(u.lm_history):
            print(f"    [{i:>2}] {h.hex()}")
    print()


def _print_aliases(
    aliases: list[SamAlias],
    machine_sid: str,
    rid_to_user: dict,
    all_groups: bool = False,
) -> None:
    r"""Render the local-groups section.

    By default only ``BUILTIN\Administrators`` (RID 544) and
    ``BUILTIN\Remote Desktop Users`` (RID 555) get a dedicated block;
    every user's full group membership is already shown inline in their
    per-user block, so the rest of the aliases would just be noise.
    Pass ``all_groups=True`` to dump every alias.
    """
    if not aliases:
        return
    ct = conf.color_theme

    def _annotate(sid: str, hot: bool = False) -> str:
        # If the SID lives in the local machine domain, resolve the RID
        # to one of the SAM users we just dumped.
        suffix = ""
        if machine_sid and sid.startswith(machine_sid + "-"):
            try:
                rid = int(sid.rsplit("-", 1)[1])
            except ValueError:
                rid = None
            if rid is not None:
                user = rid_to_user.get(rid)
                if user:
                    suffix = f"  ({user})"
        line = f"{sid}{suffix}"
        return ct.red(ct.bold(line)) if hot else line

    # The two BUILTIN aliases that are always rendered in detail.
    HOT_ALIASES = ((544, "Administrators"), (555, "Remote Desktop Users"))
    for hot_rid, label in HOT_ALIASES:
        target = next(
            (a for a in aliases if a.domain == "Builtin" and a.alias_id == hot_rid),
            None,
        )
        if target is None:
            continue
        is_admins = hot_rid == 544
        bar = ct.red if is_admins else ct.cyan
        print(bar("=" * 64))
        print(bar(ct.bold(f"{label} (BUILTIN RID {hot_rid})")))
        print(bar("=" * 64))
        if target.comment:
            print(f"  Comment: {target.comment}")
        if target.members:
            print(f"  Members ({len(target.members)}):")
            for m in target.members:
                print(f"    - {_annotate(m, hot=is_admins)}")
        else:
            print("  Members: (none)")
        print()

    if not all_groups:
        return

    _banner("Local groups (Aliases)")
    if machine_sid:
        print(f"  Machine SID: {ct.cyan(machine_sid)}")
        print()
    hot_set = {rid for rid, _ in HOT_ALIASES}
    for a in sorted(aliases, key=lambda x: (x.domain != "Builtin", x.alias_id)):
        # The two HOT aliases are already rendered above; skip empty,
        # undescribed groups to keep the output tight.
        if a.domain == "Builtin" and a.alias_id in hot_set:
            continue
        if not a.members and not a.comment:
            continue
        header = f"  {a.domain}\\{a.name}  " f"(RID {a.alias_id} / 0x{a.alias_id:x})"
        print(ct.bold(header))
        if a.comment:
            print(f"    Comment: {a.comment}")
        if a.members:
            print(f"    Members ({len(a.members)}):")
            for m in a.members:
                print(f"      - {_annotate(m)}")
        else:
            print("    Members: (none)")
        print()


# --------------------------------------------------------------------------- #
# JSON serialization
# --------------------------------------------------------------------------- #


def _jsonify(obj):
    """Recursively convert ``bytes`` values to hex strings so a
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


def samhive(
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
    all_groups: bool = False,
):
    r"""
    Dump local SAM accounts (LM/NT hashes plus all metadata), the
    domain-level password policy and the local groups (aliases) from a
    remote Windows host through the Remote Registry service.

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
    :param pwdump: emit pwdump-style ``user:rid:lm:nt:::`` lines instead
        of the full human-readable view (compatible with impacket /
        secretsdump output)
    :param json_out: emit the entire dump as JSON instead of the
        human-readable view (useful for piping into jq, etc.)
    :param color: emit ANSI colors in the human-readable view; pass
        ``--no-color`` on the CLI to turn this off
    :param timeout: SMB / RRP timeout
    :param all_groups: also include every other local group in the
        groups section of the output. By default only
        ``BUILTIN\Administrators`` (RID 544) and
        ``BUILTIN\Remote Desktop Users`` (RID 555) get a dedicated
        block, since each user's full group membership is already shown
        inline in their per-user block.
    """
    if debug:
        log_runtime.setLevel(logging.DEBUG)

    # Color is on for the human-readable view; off for pwdump / JSON
    # (those are machine-consumed) and off when piped or --no-color.
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
        # Backup privilege is required to read SAM/SECURITY hives and
        # the LSA placeholder Class strings.
        client.backup(activate=True)

        boot_key = get_boot_key(client)
        log_runtime.debug("BootKey = %s", boot_key.hex())

        domain_f = _read_value(client, "SAM\\SAM\\Domains\\Account", "F")
        hashed_bk = derive_hashed_bootkey(domain_f, boot_key)
        log_runtime.debug("Hashed BootKey = %s", hashed_bk.hex())

        domain_policy = _parse_domain_f(domain_f)
        users = dump_users(client, hashed_bk)
        aliases = dump_aliases(client)
        machine_sid = _get_machine_sid(client)
    finally:
        try:
            client.close()
        except Exception:
            pass

    if pwdump:
        for u in users:
            print(f"{u.username}:{u.rid}:{u.lm_hash.hex()}:" f"{u.nt_hash.hex()}:::")
        return

    if json_out:
        import json as _json

        print(
            _json.dumps(
                _jsonify(
                    {
                        "boot_key": boot_key,
                        "hashed_boot_key": hashed_bk,
                        "machine_sid": machine_sid,
                        "domain_policy": asdict(domain_policy),
                        "users": [asdict(u) for u in users],
                        "aliases": [asdict(a) for a in aliases],
                    }
                ),
                indent=2,
            )
        )
        return

    # Build a full RID -> [group display name] mapping for the inline
    # "Member of:" line in each user block, plus the set of RIDs that
    # are members of BUILTIN\Administrators so the per-user view can
    # flag them at a glance.
    admin_rids: set[int] = set()
    rid_to_groups: dict[int, list[str]] = {}
    for a in aliases:
        for sid in a.members:
            if not (machine_sid and sid.startswith(machine_sid + "-")):
                continue
            try:
                rid = int(sid.rsplit("-", 1)[1])
            except ValueError:
                continue
            rid_to_groups.setdefault(rid, []).append(f"{a.domain}\\{a.name}")
            if a.domain == "Builtin" and a.alias_id == 544:
                admin_rids.add(rid)

    ct = conf.color_theme
    print(f"BootKey       : {ct.cyan(boot_key.hex())}")
    print(f"HashedBootKey : {ct.cyan(hashed_bk.hex())}")
    if machine_sid:
        print(f"Machine SID   : {ct.cyan(machine_sid)}")
    print()
    _print_domain(domain_policy)
    for u in users:
        _print_user(u, admin_rids, rid_to_groups)
    rid_to_user = {u.rid: u.username for u in users}
    _print_aliases(
        aliases,
        machine_sid,
        rid_to_user,
        all_groups=all_groups,
    )


def main():
    """
    Main entry point
    """
    from scapy.utils import AutoArgparse

    conf.exts.load("scapy-red")
    AutoArgparse(samhive)


# For autocompletion generation
AUTOCOMPLETE_GEN = samhive

if __name__ == "__main__":
    main()
