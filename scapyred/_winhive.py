# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy RED
# See https://scapy.net/ for more information
# Copyright (C) github/Ebrix

r"""
Shared helpers for the SAM and SECURITY hive dumpers.

Both :mod:`scapyred.samhive` and :mod:`scapyred.securityhive` need:

  - little-endian struct readers (``_u16``, ``_u32``, ``_u64``, ``_i64``)
  - a small registry-value reader on top of :class:`RegClient`
  - the BootKey extraction routine (Class strings of the four LSA
    placeholder subkeys + permutation), since both hives are decrypted
    with secrets ultimately rooted in that 16-byte value
  - a couple of output helpers (the cyan-bordered banner)

This module is private (leading underscore in its name) - external
callers should consume the public APIs of the two hive modules instead.
"""

import struct

from scapy.config import conf

from scapyred.winreg import RegClient


# --------------------------------------------------------------------------- #
# Struct readers
# --------------------------------------------------------------------------- #


def _u16(buf: bytes, off: int) -> int:
    return struct.unpack("<H", buf[off : off + 2])[0]


def _u32(buf: bytes, off: int) -> int:
    return struct.unpack("<L", buf[off : off + 4])[0]


def _u64(buf: bytes, off: int) -> int:
    return struct.unpack("<Q", buf[off : off + 8])[0]


def _i64(buf: bytes, off: int) -> int:
    return struct.unpack("<q", buf[off : off + 8])[0]


# --------------------------------------------------------------------------- #
# Registry value access
# --------------------------------------------------------------------------- #


def _read_value(client: RegClient, subkey: str, value_name: str) -> bytes:
    r"""Return the binary blob stored under ``subkey\value_name``."""
    for entry in client.cat(subkey):
        if entry.reg_name == value_name:
            return entry.reg_data
    raise RuntimeError(f"{subkey}\\{value_name} not found")


def _read_default_value(client: RegClient, subkey: str) -> bytes:
    """Return the default (unnamed) value of a registry subkey.

    LSA secrets are stored as the default value of subkeys like
    ``SECURITY\\Policy\\Secrets\\<NAME>\\CurrVal``; the registry exposes
    them with an empty name (sometimes ``None`` depending on the
    dispatch path)."""
    for entry in client.cat(subkey):
        if entry.reg_name in ("", None, "@"):
            return entry.reg_data
    raise RuntimeError(f"{subkey} has no default value")


# --------------------------------------------------------------------------- #
# BootKey
# --------------------------------------------------------------------------- #
#
# The BootKey is a 16-byte secret derived from the *Class strings* of
# four placeholder subkeys living under
# ``HKLM\SYSTEM\CurrentControlSet\Control\Lsa``. Each Class string is a
# zero-terminated ASCII hex string of 8 chars (= 4 raw bytes), so the
# four together yield the 16-byte "scrambled" key, which is then
# permuted into the real BootKey via :data:`_BOOTKEY_PERMUTATION`.
#
# Reference: B. Dolan-Gavitt, "SysKey and the SAM",
# http://moyix.blogspot.com/2008/02/syskey-and-sam.html

# Permutation applied to the raw 16-byte string assembled from the four
# LSA Class strings.
_BOOTKEY_PERMUTATION = [
    0x8,
    0x5,
    0x4,
    0x2,
    0xB,
    0x9,
    0xD,
    0x3,
    0x0,
    0x6,
    0x1,
    0xC,
    0xE,
    0xA,
    0xF,
    0x7,
]


def _read_lsa_class(client: RegClient, name: str) -> bytes:
    """
    Read one of the four LSA placeholder subkeys' Class string and
    return its 4 raw bytes.

    :param client: a connected :class:`RegClient` mounted on HKLM with
                   the backup privilege enabled.
    :param name: ``"JD"``, ``"Skew1"``, ``"GBG"`` or ``"Data"``.
    """
    info = client.query_info(f"SYSTEM\\CurrentControlSet\\Control\\Lsa\\{name}")
    if info is None:
        raise RuntimeError(f"Could not query info on Lsa\\{name}")
    raw = info.valueof("lpClassOut.Buffer")
    if raw is None:
        raise RuntimeError(f"Lsa\\{name} has no Class string")
    if isinstance(raw, bytes):
        hex_str = raw.rstrip(b"\x00").decode("ascii")
    else:
        hex_str = raw.rstrip("\x00")
    return bytes.fromhex(hex_str)


def get_boot_key(client: RegClient) -> bytes:
    """
    Reconstruct the host BootKey by reading the Class strings of the
    four LSA placeholder subkeys and applying the permutation.
    """
    scrambled = b"".join(
        _read_lsa_class(client, name) for name in ("JD", "Skew1", "GBG", "Data")
    )
    if len(scrambled) != 16:
        raise RuntimeError(
            f"Unexpected scrambled BootKey length: {len(scrambled)} "
            "(should be 16). Make sure the backup privilege is enabled."
        )
    return bytes(scrambled[i] for i in _BOOTKEY_PERMUTATION)


# --------------------------------------------------------------------------- #
# Output helpers
# --------------------------------------------------------------------------- #


def _banner(title: str) -> None:
    """Print a cyan-bordered, bold-title section banner."""
    ct = conf.color_theme
    print(ct.cyan("=" * 64))
    print(ct.bold(title))
    print(ct.cyan("=" * 64))
