# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy RED
# See https://scapy.net/ for more information
# Copyright (C) github/Ebrix

r"""
Offline Windows Registry hive (REGF) format.

Windows registry hives - the ``.reg`` files produced by
:meth:`scapyred.winreg.RegClient.save` (``BaseRegSaveKey``) as well as the
on-disk ``SAM`` / ``SECURITY`` / ``SYSTEM`` / ``SOFTWARE`` / ``NTUSER.DAT``
hives - all use the *REGF* binary container. Nothing in Scapy itself parses
it (``scapy.layers.windows.registry`` is 100% MS-RRP RPC), so this module
provides the missing offline decoder as Scapy ``Packet`` classes plus a thin
random-access reader, :class:`RegistryHive`.

The on-disk layout is not officially documented by Microsoft; the structures
here are reconstructed from the usual public sources:

- ``WinReg`` / hive format notes, Willi Ballenthin & Timothy Morgan
  (https://github.com/msuhanov/regf) - the most complete free spec.
- ``impacket.winregistry`` (Fortra / SecureAuth) - reference Python decoder
  used for cross-validation in this project's tests.
- ``Velocidex/regparser`` (Mike Cohen) - independent Go decoder.

Layout in a nutshell
---------------------

- A 4096-byte *base block* (``regf``) at offset 0 carries the version and the
  **root cell offset** (relative to the start of the hive-bins data at 0x1000).
- The hive-bins data is a sequence of 4096-byte-aligned *hbin* blocks, each a
  bag of *cells*.
- A cell is ``<int32 size><payload>``; a **negative** size means allocated.
  ``abs(size)`` counts the 4-byte size field. Every offset stored inside a
  record is relative to 0x1000, i.e. ``file_offset = 0x1000 + cell_offset``.
- Records are tagged by a 2-byte ASCII signature at the start of the payload:
  ``nk`` (key node), ``vk`` (value), ``sk`` (security), ``lf``/``lh``/``li``/
  ``ri`` (subkey lists), ``db`` (big data).
"""

import mmap
import struct

from scapy.error import log_runtime
from scapy.packet import Packet
from scapy.fields import (
    LEIntField,
    LELongField,
    LEShortField,
    StrFixedLenField,
    StrLenField,
    XLEIntField,
)


# Offsets stored in records are relative to the start of the hive-bins data.
HBIN_START = 0x1000
# Sentinel used by the format for "no such cell".
INVALID_OFFSET = 0xFFFFFFFF
# Maximum payload a single data cell can hold before big-data (``db``) is used.
BIG_DATA_THRESHOLD = 16344
BIG_DATA_SEGMENT = 16344


# --------------------------------------------------------------------------- #
# Base block
# --------------------------------------------------------------------------- #
#
# The hbin block headers (``hbin`` magic + offset + size) are deliberately not
# modeled: cells are addressed directly relative to the hive-bins data start
# (0x1000), so the reader never has to walk the hbin chain.


class REGF_Header(Packet):
    """REGF base block (first 4096 bytes of the file)."""

    name = "REGF_Header"
    fields_desc = [
        StrFixedLenField("magic", b"regf", 4),
        LEIntField("primary_seqnum", 0),
        LEIntField("secondary_seqnum", 0),
        LELongField("last_modified", 0),
        LEIntField("major_version", 1),
        LEIntField("minor_version", 3),
        LEIntField("file_type", 0),
        LEIntField("file_format", 1),
        XLEIntField("root_cell_offset", 0),
        LEIntField("hive_bins_size", 0),
        LEIntField("clustering_factor", 0),
        StrFixedLenField("file_name", b"", 64),
    ]

    def extract_padding(self, s):
        # The remaining ~3.9KB of the base block is reserved / checksum; we
        # never need it, so don't drag it around as a payload.
        return b"", None


# --------------------------------------------------------------------------- #
# Records
# --------------------------------------------------------------------------- #


class NK_Record(Packet):
    r"""Key node (``nk``) - one registry key."""

    name = "NK_Record"
    fields_desc = [
        StrFixedLenField("signature", b"nk", 2),
        LEShortField("flags", 0),
        LELongField("last_written", 0),
        LEIntField("access_bits", 0),
        XLEIntField("parent_offset", INVALID_OFFSET),
        LEIntField("num_subkeys", 0),
        LEIntField("num_volatile_subkeys", 0),
        XLEIntField("subkeys_list_offset", INVALID_OFFSET),
        XLEIntField("volatile_subkeys_offset", INVALID_OFFSET),
        LEIntField("num_values", 0),
        XLEIntField("values_list_offset", INVALID_OFFSET),
        XLEIntField("security_offset", INVALID_OFFSET),
        XLEIntField("class_offset", INVALID_OFFSET),
        LEIntField("largest_subkey_name_len", 0),
        LEIntField("largest_subkey_class_len", 0),
        LEIntField("largest_value_name_len", 0),
        LEIntField("largest_value_data_len", 0),
        LEIntField("workvar", 0),
        LEShortField("key_name_length", 0),
        LEShortField("class_name_length", 0),
        StrLenField("key_name", b"", length_from=lambda p: p.key_name_length),
    ]

    # Flag bit: key name is stored as Latin-1 rather than UTF-16LE.
    COMP_NAME = 0x0020

    def name_str(self) -> str:
        """Decode the key name honoring the ASCII-vs-UTF16 flag."""
        if self.flags & self.COMP_NAME:
            return self.key_name.decode("latin-1", "replace")
        return self.key_name.decode("utf-16-le", "replace")

    def extract_padding(self, s):
        return b"", None


class VK_Record(Packet):
    r"""Value (``vk``) - one named value inside a key."""

    name = "VK_Record"
    fields_desc = [
        StrFixedLenField("signature", b"vk", 2),
        LEShortField("name_length", 0),
        LEIntField("data_size", 0),
        XLEIntField("data_offset", 0),
        LEIntField("data_type", 0),
        LEShortField("flags", 0),
        LEShortField("spare", 0),
        StrLenField("value_name", b"", length_from=lambda p: p.name_length),
    ]

    # Flag bit: value name is stored as Latin-1 rather than UTF-16LE.
    COMP_NAME = 0x0001
    # High bit of ``data_size``: the (<=4 byte) data lives inline in
    # ``data_offset`` instead of a separate cell.
    INLINE = 0x80000000

    def name_str(self) -> str:
        """Decode the value name; empty name means the '(Default)' value."""
        if self.name_length == 0:
            return ""
        if self.flags & self.COMP_NAME:
            return self.value_name.decode("latin-1", "replace")
        return self.value_name.decode("utf-16-le", "replace")

    def extract_padding(self, s):
        return b"", None


class SK_Record(Packet):
    r"""Security descriptor holder (``sk``)."""

    name = "SK_Record"
    fields_desc = [
        StrFixedLenField("signature", b"sk", 2),
        LEShortField("reserved", 0),
        XLEIntField("flink", 0),
        XLEIntField("blink", 0),
        LEIntField("ref_count", 0),
        LEIntField("sd_size", 0),
        StrLenField("descriptor", b"", length_from=lambda p: p.sd_size),
    ]

    def extract_padding(self, s):
        return b"", None


class DB_Record(Packet):
    r"""Big-data indirection block (``db``) for values > 16344 bytes."""

    name = "DB_Record"
    fields_desc = [
        StrFixedLenField("signature", b"db", 2),
        LEShortField("num_segments", 0),
        XLEIntField("segment_list_offset", INVALID_OFFSET),
    ]

    def extract_padding(self, s):
        return b"", None


# --------------------------------------------------------------------------- #
# Subkey lists
# --------------------------------------------------------------------------- #


class HashLeaf(Packet):
    r"""
    Hash leaf subkey list (``lf`` / ``lh``): points straight at ``nk`` cells.

    Each entry is ``<u32 key-node offset><u32 hash>``; only the offset matters
    for enumeration. Parsed as a raw block (rather than a ``PacketListField``,
    which is capped at ``conf.max_list_count``) since keys can have thousands
    of subkeys.
    """

    name = "HashLeaf"
    fields_desc = [
        StrFixedLenField("signature", b"lf", 2),
        LEShortField("count", 0),
        StrLenField("raw", b"", length_from=lambda p: p.count * 8),
    ]

    def offsets(self) -> tuple:
        vals = struct.unpack_from("<%dI" % (self.count * 2), self.raw, 0)
        return vals[0::2]

    def extract_padding(self, s):
        return b"", None


class IndexList(Packet):
    r"""Index subkey list (``li`` -> ``nk`` cells, or ``ri`` -> other lists)."""

    name = "IndexList"
    fields_desc = [
        StrFixedLenField("signature", b"li", 2),
        LEShortField("count", 0),
        StrLenField("raw", b"", length_from=lambda p: p.count * 4),
    ]

    def offsets(self) -> tuple:
        return struct.unpack_from("<%dI" % self.count, self.raw, 0)

    def extract_padding(self, s):
        return b"", None


# --------------------------------------------------------------------------- #
# Random-access reader
# --------------------------------------------------------------------------- #


class RegistryHive:
    r"""
    Random-access reader over a REGF hive file.

    Opens the hive (memory-mapped), parses the base block, and exposes the
    handful of primitive lookups the offline browser needs:
    :meth:`root_key`, :meth:`subkeys`, :meth:`values`, :meth:`value_data`
    and :meth:`security`.

    :param path: path to the ``.reg`` / hive file on disk.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self._f = open(path, "rb")
        try:
            self.data = mmap.mmap(self._f.fileno(), 0, access=mmap.ACCESS_READ)
        except ValueError:
            # Empty file -> mmap refuses; fall back to bytes so the error is
            # a clean "not a hive" rather than an mmap traceback.
            self.data = self._f.read()

        self.header = REGF_Header(self.data[:512])
        if self.header.magic != b"regf":
            raise ValueError(f"{path!r} is not a REGF hive (bad magic)")
        self.root_cell_offset = self.header.root_cell_offset

    # -- low level -------------------------------------------------------- #

    def _cell_payload(self, offset: int) -> bytes:
        r"""
        Return the payload bytes (signature onward) of the cell at ``offset``
        (relative to the hive-bins data), i.e. without the 4-byte size field.
        """
        if offset == INVALID_OFFSET:
            raise ValueError("attempt to read the INVALID cell offset")
        abs_off = HBIN_START + offset
        (size,) = struct.unpack_from("<i", self.data, abs_off)
        size = abs(size)
        if size < 4:
            raise ValueError(f"corrupt cell size {size} at offset {hex(offset)}")
        return self.data[abs_off + 4 : abs_off + size]

    # -- keys ------------------------------------------------------------- #

    def root_key(self) -> NK_Record:
        """Return the hive's root key node."""
        return NK_Record(self._cell_payload(self.root_cell_offset))

    def subkeys(self, nk: NK_Record) -> list:
        """Return the list of :class:`NK_Record` children of ``nk``."""
        res: list = []
        if nk.num_subkeys == 0 or nk.subkeys_list_offset == INVALID_OFFSET:
            return res
        self._collect_subkeys(nk.subkeys_list_offset, res)
        return res

    def _collect_subkeys(self, offset: int, res: list) -> None:
        payload = self._cell_payload(offset)
        sig = payload[:2]
        if sig in (b"lf", b"lh"):
            for off in HashLeaf(payload).offsets():
                res.append(NK_Record(self._cell_payload(off)))
        elif sig == b"li":
            for off in IndexList(payload).offsets():
                res.append(NK_Record(self._cell_payload(off)))
        elif sig == b"ri":
            # Root index: each entry points at another (lf/lh/li) subkey list.
            for off in IndexList(payload).offsets():
                self._collect_subkeys(off, res)
        else:
            log_runtime.warning("Unknown subkey-list signature %r", sig)

    # -- values ----------------------------------------------------------- #

    def values(self, nk: NK_Record) -> list:
        """Return the list of :class:`VK_Record` values of ``nk``."""
        res: list = []
        if nk.num_values == 0 or nk.values_list_offset == INVALID_OFFSET:
            return res
        payload = self._cell_payload(nk.values_list_offset)
        offsets = struct.unpack_from("<%dI" % nk.num_values, payload, 0)
        for voff in offsets:
            if voff == INVALID_OFFSET:
                continue
            res.append(VK_Record(self._cell_payload(voff)))
        return res

    def value_data(self, vk: VK_Record) -> bytes:
        """Return the raw data bytes of value ``vk`` (resolving big-data)."""
        raw_size = vk.data_size
        size = raw_size & 0x7FFFFFFF
        if raw_size & VK_Record.INLINE:
            # <=4 bytes stored directly in the offset field.
            return struct.pack("<I", vk.data_offset)[:size]
        if size == 0 or vk.data_offset == INVALID_OFFSET:
            return b""
        if size > BIG_DATA_THRESHOLD:
            return self._big_data(vk.data_offset, size)
        return self._cell_payload(vk.data_offset)[:size]

    def _big_data(self, db_offset: int, size: int) -> bytes:
        payload = self._cell_payload(db_offset)
        if payload[:2] != b"db":
            # Some producers store big data as a single oversized cell.
            return payload[:size]
        db = DB_Record(payload)
        seg_payload = self._cell_payload(db.segment_list_offset)
        seg_offsets = struct.unpack_from("<%dI" % db.num_segments, seg_payload, 0)
        out = bytearray()
        remaining = size
        for soff in seg_offsets:
            if remaining <= 0:
                break
            chunk = self._cell_payload(soff)
            take = min(len(chunk), BIG_DATA_SEGMENT, remaining)
            out += chunk[:take]
            remaining -= take
        return bytes(out[:size])

    def class_name(self, nk: NK_Record) -> str | None:
        """Return the (UTF-16LE) class string attached to ``nk``, if any."""
        if nk.class_offset == INVALID_OFFSET or nk.class_name_length == 0:
            return None
        raw = self._cell_payload(nk.class_offset)[: nk.class_name_length]
        try:
            return raw.decode("utf-16-le")
        except UnicodeDecodeError:
            return raw.hex()

    # -- security --------------------------------------------------------- #

    def security(self, nk: NK_Record) -> SK_Record | None:
        """Return the ``sk`` record protecting ``nk``, or None."""
        if nk.security_offset == INVALID_OFFSET:
            return None
        return SK_Record(self._cell_payload(nk.security_offset))

    # -- lifecycle -------------------------------------------------------- #

    def close(self) -> None:
        try:
            if isinstance(self.data, mmap.mmap):
                self.data.close()
        finally:
            self._f.close()
