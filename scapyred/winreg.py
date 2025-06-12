# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy RED
# See https://scapy.net/ for more information
# Copyright (C) github/Ebrix

"""
Windows Registry Client over RPC
"""

import os
import logging
import sys

from dataclasses import dataclass
from enum import IntFlag, Enum
from ctypes.wintypes import PFILETIME
from typing import NoReturn, Self
from pathlib import PureWindowsPath
from datetime import datetime, timezone
from time import sleep

# Load scapy-rpc
from scapy.config import conf

conf.exts.load("scapy-rpc")

# pylint: disable=wrong-import-position
from scapy.error import Scapy_Exception
from scapy.utils import (
    CLIUtil,
)

from scapy.layers.dcerpc import RPC_C_AUTHN_LEVEL
from scapy.layers.spnego import SPNEGOSSP
from scapy.layers.windows.security import (
    SECURITY_DESCRIPTOR,
    WINNT_ACCESS_ALLOWED_ACE,
    WINNT_ACE_HEADER,
    WINNT_ACL,
    WINNT_SID,
)
from scapy.layers.msrpce.raw.ms_rrp import (  # noqa: E402
    BaseRegQueryInfoKey_Response,
    NDRContextHandle,
    NDRIntField,
    PRPC_SECURITY_ATTRIBUTES,
    RPC_SECURITY_DESCRIPTOR,
)
from scapy.layers.windows.registry import (  # noqa: E402
    RegEntry,
    RegOptions,
    RegType,
    RootKeys,
    RRP_Client,
)

# Set log level to benefit from Scapy warnings
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

# Create a stream handler
stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setLevel(logging.INFO)

# Create a formatter and attach it
formatter_sh = logging.Formatter("[%(levelname)s] %(message)s")
stream_handler.setFormatter(formatter_sh)

# Add the stream handler
logger.addHandler(stream_handler)

# Create a file handler
file_handler = logging.FileHandler("winreg.log")
file_handler.setLevel(logging.DEBUG)

# Create a formatter and attach it
formatter_fh = logging.Formatter("[%(levelname)s][%(funcName)s] %(message)s")
file_handler.setFormatter(formatter_fh)

# Add the file handler
logger.addHandler(file_handler)


logger.debug("Starting scapy-windows-registry module")


def from_filetime_to_datetime(lp_filetime: PFILETIME) -> str:
    """
    Convert a filetime to a human readable date
    """

    filetime = lp_filetime.dwLowDateTime + (lp_filetime.dwHighDateTime << 32)
    # Filetime is in 100ns intervals since 1601-01-01
    # Convert to seconds since epoch
    seconds = (filetime - 116444736000000000) // 10000000
    return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def is_int_string(value: str) -> bool:
    """Check if the value in an int cast as a str"""
    try:
        int(value)
        return True
    except ValueError:
        return False


# Global constant used to easily record
# the root keys available and prevent typos
AVAILABLE_ROOT_KEYS: list[str] = [
    RootKeys.HKEY_LOCAL_MACHINE,
    RootKeys.HKEY_CURRENT_USER,
    RootKeys.HKEY_USERS,
    RootKeys.HKEY_CLASSES_ROOT,
    RootKeys.HKEY_CURRENT_CONFIG,
    RootKeys.HKEY_PERFORMANCE_DATA,
    RootKeys.HKEY_PERFORMANCE_TEXT,
    RootKeys.HKEY_PERFORMANCE_NLSTEXT,
]


class WellKnownSIDs(Enum):
    """
    Well-known SIDs.

    .. notes::
    This class should be filled with more values as needs arise
    """

    SY = WINNT_SID.fromstr("S-1-5-18")  # Local System
    BA = WINNT_SID.fromstr("S-1-5-32-544")  # Built-in Administrators


DEFAULT_SECURITY_DESCRIPTOR = SECURITY_DESCRIPTOR(
    Control=0x1000 | 0x8000 | 0x4,
    # OwnerSid=WellKnownSIDs.SY.value,  # Local System SID
    # GroupSid=WellKnownSIDs.SY.value,  # Local System SID
    DACL=WINNT_ACL(
        AclRevision=2,
        Sbz1=0,
        Aces=[
            WINNT_ACE_HEADER(
                AceType=0x0,  # ACCESS_ALLOWED_ACE_TYPE
                AceFlags=0x0,  # No flags
            )
            / WINNT_ACCESS_ALLOWED_ACE(
                Mask=0x10000000,  # GA
                Sid=WellKnownSIDs.BA.value,  # Built-in Administrators SID
            ),
        ],
    ),
    ndr64=True,
)

# For now we force the AclSize to the length of the Acl
# DEFAULT_SECURITY_DESCRIPTOR.Data[0][1][WINNT_ACL].AclSize = len(
#     DEFAULT_SECURITY_DESCRIPTOR.Data[0][1][WINNT_ACL]
# )


@dataclass
class CacheElt:
    """
    Cache element to store the handle and the subkey path
    """

    # Handle on a remote object
    handle: NDRContextHandle

    # Requested AccessRights for this handle
    access: int

    # List of elements returned by the server
    # using this handle. For example a list of subkeys or values.
    values: list


@conf.commands.register
class RegClient(CLIUtil):
    r"""
    A simple registry CLI

    :param target: can be a hostname, the IPv4 or the IPv6 to connect to
    :param UPN: the upn to use (DOMAIN/USER, DOMAIN\USER, USER@DOMAIN or USER)
    :param password: (string) if provided, used for auth
    :param guest: use guest mode (over NTLM)
    :param ssp: if provided, use this SSP for auth.
    :param kerberos: if available, whether to use Kerberos or not
    :param kerberos_required: require kerberos
    :param port: the TCP port. default 445
    :param HashNt: (bytes) if provided, used for auth (NTLM)
    :param ST: if provided, the service ticket to use (Kerberos)
    :param KEY: if provided, the session key associated to the ticket (Kerberos)
    :param cli: CLI mode (default True). False to use for scripting
    :param rootKey: the root key to get a handle to (HKLM, HKCU, etc.),
                    in CLI mode you can chose it later
    :param subKey: the subkey to use (default None, in CLI mode you can chose it later)

    Some additional SMB parameters are available under help(SMB_Client). Some of
    them include the following:

    :param REQUIRE_ENCRYPTION: requires encryption.
    """

    def __init__(
        self,
        target: str,
        UPN: str = None,
        password: str = None,
        kerberos: bool = True,
        kerberos_required: bool = False,
        HashNt: str = None,
        HashAes128Sha96: str = None,
        HashAes256Sha96: str = None,
        use_krb5ccname: bool = False,
        port: int = 445,
        timeout: int = 2,
        debug: bool = False,
        ssp=None,
        cli=True,
        rootKey: str = None,
        subKey: str = None,
        # SMB arguments
        **kwargs,
    ) -> Self | NoReturn:

        if cli:
            self._depcheck()

        assert UPN or ssp, "Either UPN or ssp must be provided !"
        # Do we need to build a SSP?
        if ssp is None:
            # Create the SSP
            ssp = SPNEGOSSP.from_cli_arguments(
                UPN=UPN,
                target=target,
                password=password,
                HashNt=HashNt,
                HashAes256Sha96=HashAes256Sha96,
                HashAes128Sha96=HashAes128Sha96,
                kerberos_required=kerberos_required,
                use_krb5ccname=use_krb5ccname,
            )

        # Create RRP client
        self.client = RRP_Client(
            auth_level=RPC_C_AUTHN_LEVEL.PKT_PRIVACY,
            ssp=ssp,
            verb=debug,
        )
        if debug:
            logger.setLevel(logging.DEBUG)
            logger.debug(
                "Connecting to %s:%d with UPN=%s, " "kerberos=%s, kerberos_required=%s",
                target,
                port,
                UPN,
                kerberos,
                kerberos_required,
            )

        self.timeout = timeout
        try:
            self.client.connect(target, timeout=self.timeout)
            self.client.bind()
        except ValueError as exc:
            logger.warning(f"""
                Remote service didn't seem to be running.
                Let's try again in 2", now that we should have trigger it. ({exc})
                """)

            sleep(2)
            self.client.connect(target, timeout=self.timeout)
            self.client.bind()
        except Scapy_Exception as exc:
            if str(3221225566) in str(exc):
                logger.error(f"""
[!] STATUS_LOGON_FAILURE - {exc}  You used:
    - UPN {UPN},
    - password {password},
    - target {target},
    - kerberos {kerberos},
    - kerberos_required {kerberos_required},
    - HashNt {HashNt},
    - HashAes128Sha96 {HashAes128Sha96},
    - HashAes256Sha96 {HashAes256Sha96},

[💡 TIPS] If you want to use a local account you may use something like:
UPN = "WORKGROUP\\\\Administrator" or
UPN = "Administrator@WORKGROUP" or
UPN = "Administrator@192.168.1.2"
""")
            raise exc
        except TimeoutError as exc:
            logger.error(
                f"[!] Timeout while connecting to {target}:{port}."
                f"Check service status. {exc}"
            )
            raise exc
        except Exception as exc:
            logger.error(f"[!] Exception while connecting: {exc}")
            raise exc

        # Session parameters
        self.cache: dict[str : dict[str, CacheElt]] = {
            "ls": dict(),
            "cat": dict(),
            "cd": dict(),
        }
        # Options for registry operations default to non-volatile
        # This means that the registry key will not be deleted
        # when the system is restarted.
        self.extra_options = RegOptions.REG_OPTION_NON_VOLATILE
        self.root_handle = {}
        self.current_root_handle = None
        self.current_subkey_handle = None
        self.expl_mode = False
        self.current_subkey_path: PureWindowsPath = PureWindowsPath("")
        self.sam_requested_access_rights = 0x2000000  # Maximum Allowed
        if rootKey in AVAILABLE_ROOT_KEYS:
            self.current_root_path = rootKey.strip()
            self.use(self.current_root_path)
        else:
            self.current_root_path = "CHOOSE ROOT KEY"
        if subKey:
            self.cd(subKey.strip())
        if cli:
            self.loop(debug=debug)

    def ps1(self) -> str:
        return f"[reg] {self.current_root_path}\\{self.current_subkey_path} > "

    @CLIUtil.addcommand()
    def close(self) -> None:
        """
        Close all connections
        """

        print("Connection closed")
        self.client.close()

    # --------------------------------------------- #
    #                   Use Root Key
    # --------------------------------------------- #

    @CLIUtil.addcommand(mono=True)
    def use(self, root_path: str) -> tuple[str, NDRContextHandle] | None:
        """
        Selects and sets the base registry key (root) to use for subsequent operations.

        Behavior:
            - Determines which registry root to use based on the prefix of `root_path`.
            - Opens the corresponding registry root handle if not already opened,
              using the appropriate request.
            - Clears the local subkey cache
            - Changes the current directory to the root of the selected registry hive.

        :param root_path: The root registry path to use. Should start with one of the
        following:
            - HKCR
            - HKLM
            - HKCU
            - HKCC
            - HKU
            - HKPD
            - HKPT
            - HKPN
        """

        root_path = RootKeys(root_path.upper().strip())

        try:
            self.current_root_handle = self.client.get_root_key_handle(
                root_path,
                sam_desired=self.sam_requested_access_rights,
                timeout=self.timeout,
            )
        except ValueError:
            # If the root key is not recognized, raise an error
            logger.error(f"Unknown root key: {root_path}")
            self.clear_all_caches()
            self.current_root_handle = None
            self.current_root_path = "CHOOSE ROOT KEY"
            self.cd("")
            return None

        self.current_root_path = root_path.value
        self.clear_all_caches()
        self.cd("")
        return self.current_root_path, self.current_root_handle

    @CLIUtil.addcomplete(use)
    def use_complete(self, root_key: str) -> list[str]:
        """
        Auto complete root key for `use`
        """
        return [
            str(rkey.value)
            for rkey in AVAILABLE_ROOT_KEYS
            if str(rkey.value).startswith(root_key.upper())
        ]

    # --------------------------------------------- #
    #                   List and Cat
    # --------------------------------------------- #

    @CLIUtil.addcommand(mono=True)
    def ls(self, subkey: str | None = None) -> list[str]:
        """
        Enumerate the subkeys of the given relative `subkey`

        :param subkey: the relative subkey to enumerate the subkey from.
                       If None, uses the current subkey path.

        :return: the list of the subkeys.
        """

        # Try to use the cache
        res = self._get_cached_elt(subkey=subkey, cache_name="ls")
        if res is None:
            return []
        elif len(res.values) != 0:
            # If the resolution was already performed,
            # no need to query again the RPC
            return res.values

        # format subkey as a string to get a subkey path
        if subkey is None:
            subkey = ""

        subkey_path = self._join_path(self.current_subkey_path, subkey)

        # Enumerate the subkeys
        logger.debug("Enumerating subkeys at %s", subkey_path)

        try:
            subkeys = self.client.enum_subkeys(res.handle, timeout=self.timeout)
            self.cache["ls"][subkey_path].values.extend(subkeys)
        except ValueError as resp_exc:
            logger.error(
                "Got status %s while enumerating keys", hex(int(resp_exc.args[0]))
            )
            c_elt = self.cache["ls"].pop(subkey_path, None)
            if c_elt is not None:
                self._close_key(c_elt.handle)
            return []

        return self.cache["ls"][subkey_path].values

    @CLIUtil.addoutput(ls)
    def ls_output(self, results: list[str]) -> None:
        """
        Print the output of 'ls'
        """
        for subkey in results:
            print(subkey)

    @CLIUtil.addcomplete(ls)
    def ls_complete(self, subkey: str) -> list[str]:
        """
        Auto-complete ls
        """
        if self._require_root_handles(silent=True):
            return []

        subkey = subkey.strip().replace("/", "\\")
        if "\\" in subkey:
            parent = "\\".join(subkey.split("\\")[:-1])
            subkey = subkey.split("\\")[-1]
        else:
            parent = ""

        return [
            str(self._join_path(parent, str(subk)))
            for subk in self.ls(parent)
            if str(subk).lower().startswith(subkey.lower())
        ]

    @CLIUtil.addcommand(mono=True)
    def cat(self, subkey: str | None = None) -> list[RegEntry]:
        """
        Enumerates and retrieves registry values for a given subkey path.

        If no subkey is specified, uses the current subkey path and caches
        results to avoid redundant RPC queries.
        Otherwise, enumerates values under the specified subkey path.

        :param subkey: the relative subkey path to enumerate.
            If None, uses the current subkey path.

        :return: a list of registry entries (as RegEntry objects) for the
            specified subkey path. Returns an empty list if the handle
            is invalid or an error occurs during enumeration.
        """

        # Try to use the cache
        res = self._get_cached_elt(subkey=subkey, cache_name="cat")
        if res is None:
            return []
        elif len(res.values) != 0:
            # If the resolution was already performed,
            # no need to query again the RPC
            return res.values

        subkey_path = self._join_path(self.current_subkey_path, subkey)

        logger.debug("Enumerating values from the %s subkey", subkey_path)
        try:
            entries = self.client.enum_values(res.handle, timeout=self.timeout)
            self.cache["cat"][subkey_path].values.extend(entries)
        except ValueError as resp_exc:
            logger.error(
                "got status %s while enumerating values", hex(int(resp_exc.args[0]))
            )
            c_elt = self.cache["cat"].pop(subkey_path, None)
            if c_elt is not None:
                self._close_key(c_elt.handle)
            return []

        return self.cache["cat"][subkey_path].values

    @CLIUtil.addoutput(cat)
    def cat_output(self, results: list[RegEntry]) -> None:
        """
        Print the output of 'cat'
        """

        if not results or len(results) == 0:
            print("No values found.")
            return

        for entry in results:
            if entry.reg_type == RegType.UNK:
                if entry.reg_name == "":
                    # Default value
                    print(
                        f"  -  {'\033[94;1m(Default)\033[0m':<28} "
                        f"{'(' + entry.reg_type.name + ' - ':<20}"
                        f"{str(entry.reg_type.real_value) + ')':<15} "
                        f"{entry.reg_data}"
                    )
                else:
                    print(
                        f"  - {entry.reg_name.strip():<20} "
                        f"{'(' + entry.reg_type.name + ' - ':<20} "
                        f"{str(entry.reg_type.real_value) + ')':<15} "
                        f"{entry.reg_data}"
                    )
            else:
                if entry.reg_name == "":
                    # Default value
                    print(
                        f"  - {'\033[94;1m(Default)\033[0m':<28} "
                        f"{'(' + entry.reg_type.name + ' - ':<20}"
                        f"{str(entry.reg_type.value) + ')':<15} "
                        f"{entry.reg_data}"
                    )
                else:
                    print(
                        f"  - {entry.reg_name.strip():<20} "
                        f"{'(' + entry.reg_type.name + ' - ':<20}"
                        f"{str(entry.reg_type.value) + ')':<15} "
                        f"{entry.reg_data}"
                    )

    @CLIUtil.addcomplete(cat)
    def cat_complete(self, subkey: str) -> list[str]:
        """
        Auto-complete cat
        """
        return self.ls_complete(subkey)

    # --------------------------------------------- #
    #                   Change Directory
    # --------------------------------------------- #

    @CLIUtil.addcommand(mono=True)
    def cd(self, subkey: str) -> None:
        """
        Change current subkey path

        :param subkey: the relative subkey to go to. Root keys shall
            not be provided here.
        """

        if subkey.strip() == "":
            # If the subkey is ".", we do not change the current subkey path
            tmp_path = PureWindowsPath()
            tmp_handle = self.get_handle_on_subkey(tmp_path)

        else:
            # Try to use the cache
            res = self._get_cached_elt(
                subkey=subkey,
                cache_name="cd",
            )
            tmp_handle = res.handle if res else None
            tmp_path = self._join_path(self.current_subkey_path, subkey)

        if tmp_handle is not None:
            # If the handle was successfully retrieved,
            # we update the current subkey path and handle
            self.current_subkey_path = tmp_path
            self.current_subkey_handle = tmp_handle
        else:
            logger.error("Could not change directory to %s", subkey)
            raise ValueError(f"Could not change directory to {subkey}")

        if self.expl_mode:
            # force the trigger of the UTILS.OUTPUT command (cd_output)
            return f"[{self.current_root_path}:\\{self.current_subkey_path}]"

    @CLIUtil.addcomplete(cd)
    def cd_complete(self, subkey: str) -> list[str]:
        """
        Auto-complete cd
        """

        return self.ls_complete(subkey)

    @CLIUtil.addoutput(cd)
    def cd_output(self, pwd) -> None:
        """
        Print the output of 'cd'
        """

        if self.expl_mode and pwd is not None:
            print(pwd)
            print("-" * 10 + " SubKeys" + "-" * 10)
            self.ls_output(self.ls())
            print("-" * 10 + " Values" + "-" * 10)
            self.cat_output(self.cat())

    @CLIUtil.addcommand()
    def exploration_mode(self) -> None:
        """
        Activate / Desactivate exploration mode: perform ls and cat
        automatically when changing directory
        """

        if self.expl_mode:
            self.expl_mode = False
            print("Exploration mode disabled")
        else:
            self.expl_mode = True
            print("Exploration mode activated")

    # --------------------------------------------- #
    #                   Get Information
    # --------------------------------------------- #

    @CLIUtil.addcommand(mono=True)
    def get_sd(self, subkey: str | None = None) -> SECURITY_DESCRIPTOR | None:
        """
        Get the security descriptor of the current subkey.
        SACL are not retrieve at this point (TODO).

        :param: the relative subkey to get the security descriptor from.
        If None, it uses the current subkey path.

        :return: the SECURITY_DESCRIPTOR object if all went well. None otherwise.
        """

        # Try to use the cache
        handle = self._get_cached_elt(subkey=subkey)
        if handle is None:
            return None

        # Log and prepare request
        logger.debug("Getting security descriptor for %s", subkey)

        try:
            sd = self.client.get_key_security(
                handle,
                timeout=self.timeout,
            )
        except ValueError as resp_exc:
            logger.error("Got status %s while getting security", hex(resp_exc.args[0]))
            return None

        return sd

    @CLIUtil.addoutput(get_sd)
    def get_sd_output(self, sd: SECURITY_DESCRIPTOR | None) -> None:
        """
        Print the output of 'get_sd'
        """

        if sd is None:
            print("No security descriptor found.")
        else:
            print("WARNING: access rights are not yet displayed :(")
            sd.show_print()

    @CLIUtil.addcomplete(get_sd)
    def get_sd_complete(self, subkey: str) -> list[str]:
        """
        Auto complete subkeys for `get_sd`
        """
        return self.ls_complete(subkey)

    @CLIUtil.addcommand(mono=True)
    def query_info(
        self, subkey: str | None = None
    ) -> BaseRegQueryInfoKey_Response | None:
        """
        Query information on the current subkey

        :param subkey: the relative subkey to query info from. If None,
            it uses the current subkey path.

        :return: BaseRegQueryInfoKey_Response object containing information
            about the subkey. Returns None if the handle is invalid or an
            error occurs during the query.
        """

        # Try to use the cache
        handle = self._get_cached_elt(subkey)
        if handle is None:
            logger.error("Could not get handle on the specified subkey.")
            return None

        # Log and request info
        logger.debug("Querying info for %s", subkey)
        try:
            resp = self.client.get_key_info(handle, timeout=self.timeout)
        except ValueError as resp_exc:
            logger.error(
                "Got status %s while querying info", hex(int(resp_exc.args[0]))
            )
            return None

        return resp

    @CLIUtil.addoutput(query_info)
    def query_info_output(self, info: None) -> None:
        """
        Print the output of 'query_info'
        """

        if info is None:
            print("No information found.")
            return
        class_info = info.valueof("lpClassOut.Buffer")
        print(f"""
Info on key:
  - Number of subkeys: {info.lpcSubKeys}
  - Length of the longest subkey name (in bytes): {info.lpcbMaxSubKeyLen}
  - Number of values: {info.lpcValues}
  - Length of the longest value name (in bytes): {info.lpcbMaxValueNameLen}
  - Last write time: {from_filetime_to_datetime(info.lpftLastWriteTime)}
  - Class: {bytes.fromhex(class_info[:-1].decode())
            if class_info is not None
            else "None"}
""")

    @CLIUtil.addcomplete(query_info)
    def query_info_complete(self, subkey: str) -> list[str]:
        """
        Auto complete subkeys for `query_info`
        """
        return self.ls_complete(subkey)

    @CLIUtil.addcommand()
    def version(self) -> NDRIntField:
        """
        Get remote registry server version of the current subkey
        """

        logger.debug("Getting remote registry server version")
        return self.client.get_version(
            self.current_subkey_handle, timeout=self.timeout
        ).lpdwVersion

    @CLIUtil.addoutput(version)
    def version_output(self, version: int) -> None:
        """
        Print the output of 'version'
        """

        print(f"Remote registry server version: {version}")

    # --------------------------------------------- #
    #                  Modify                       #
    # --------------------------------------------- #

    @CLIUtil.addcommand()
    def set_value(
        self,
        value_name: str,
        value_type: RegType | str,
        value_data: str,
        subkey: str | None = None,
        is_not_default: bool = False,
    ) -> bool | None:
        """
        Set a registry value in the current subkey.
        If no subkey is specified, it uses the current subkey path.

        :param value_name: name of the value to set. Use "(Default)"
            for the default value.
        :param value_type: type of the value to set.
            REG_SZ = 1  # Unicode string
            REG_EXPAND_SZ = 2  # Unicode string with environment variable expansion
            REG_BINARY = 3  # Binary data
            REG_DWORD = 4  # 32-bit unsigned integer
            REG_DWORD_BIG_ENDIAN = 5  # 32-bit unsigned integer in big-endian format
            REG_LINK = 6  # Symbolic link
            REG_MULTI_SZ = 7  # Multiple Unicode strings
            REG_QWORD = 11  # 64-bit unsigned integer

            Can be a RegType or a string representing the type.
        :param value_data: data of the value to set. The input will be encoded based
            on the type.
        :param subkey: relative subkey to set the value in
        :param is_not_default: if set, the value_name will not be converted
            to the default value in the case were it equals "(Default)".

        :return: returns True if all went well, None otherwise.
        """

        # Get the value type
        value_type = RegType.fromstr(value_type)
        if value_type == RegType.UNK:
            logger.error("Unknown registry type: %s", value_type)
            raise ValueError(value_type)

        # Try to use the cache
        handle = self._get_cached_elt(
            subkey=subkey, desired_access=0x20006  # KEY_WRITE
        )
        if handle is None:
            logger.error("Could not get handle on the specified subkey.")
            return None

        if subkey is None:
            subkey_path = self.current_subkey_path
        else:
            subkey_path = self._join_path(self.current_subkey_path, subkey)

        # look for default value
        if value_name == "(Default)" and not is_not_default:
            value_name = ""

        # Log and send request
        logger.debug(
            "Setting value %s of type %s in %s",
            value_name,
            value_type.name,
            subkey_path,
        )

        try:
            if isinstance(value_data, str):
                self.client.set_value(
                    handle,
                    RegEntry.fromstr(
                        reg_name=value_name,
                        reg_type=value_type,
                        data=value_data,
                    ),
                    timeout=self.timeout,
                )
            elif isinstance(value_data, bytes):
                self.client.set_value(
                    handle,
                    RegEntry.frombytes(
                        reg_name=value_name,
                        reg_type=value_type,
                        data=value_data,
                    ),
                    timeout=self.timeout,
                )
            else:
                self.client.set_value(
                    handle,
                    RegEntry(
                        reg_name=value_name,
                        reg_type=value_type,
                        reg_data=value_data,
                    ),
                    timeout=self.timeout,
                )

        except ValueError as resp_exc:
            logger.error("Got status %s while setting value", hex(resp_exc.args[0]))
            # We remove the entry from the cache if it exists
            # Even if the response status is not OK, we want to remove it
            if subkey_path in self.cache["cat"]:
                c_elt = self.cache["cat"].pop(subkey_path, None)
                if c_elt is not None:
                    self._close_key(c_elt.handle)
            return None

        # We remove the entry from the cache if it exists
        # Even if the response status is not OK, we want to remove it
        if subkey_path in self.cache["cat"]:
            c_elt = self.cache["cat"].pop(subkey_path, None)
            if c_elt is not None:
                self._close_key(c_elt.handle)

        return True

    @CLIUtil.addcomplete(set_value)
    def set_value_complete(self, param_to_complete: list[str]) -> list[str]:
        """
        Auto-complete delete_value
        """
        reg_type_dict = {
            "reg": [
                "SZ",
                "EXPAND_SZ",
                "BINARY",
                "DWORD",
                "DWORD_BIG_ENDIAN",
                "LINK",
                "MULTI_SZ",
                "QWORD",
            ],
            "int": {
                "1": "REG_SZ",
                "2": "REG_EXPAND_SZ",
                "3": "REG_BINARY",
                "4": "REG_DWORD",
                "5": "REG_DWORD_BIG_ENDIAN",
                "6": "REG_LINK",
                "7": "REG_MULTI_SZ",
                "11": "REG_QWORD",
            },
        }

        if self._require_root_handles(silent=True):
            return []

        if len(param_to_complete) == 1:
            value_name = param_to_complete[0].strip()
            value_name = value_name.strip()
            return [
                str(value.reg_name)
                for value in self.cat()
                if str(value.reg_name).lower().startswith(value_name.lower())
            ]

        elif len(param_to_complete) == 2:
            reg_type = param_to_complete[1].strip().upper()
            if reg_type.startswith("R"):
                if reg_type.startswith("REG_"):
                    reg_type = reg_type[4:]
                if reg_type.startswith("REG"):
                    reg_type = reg_type[3:]
                if reg_type.startswith("RE"):
                    reg_type = reg_type[2:]
                if reg_type.startswith("R"):
                    reg_type = reg_type[1:]

                return [
                    "REG_" + rtype
                    for rtype in reg_type_dict["reg"]
                    if rtype.startswith(reg_type)
                ]
            elif not is_int_string(reg_type):
                return [
                    "REG_" + rtype
                    for rtype in reg_type_dict["reg"]
                    if rtype.startswith(reg_type)
                ]
            else:
                return [
                    rtype_name
                    for rtype_int, rtype_name in reg_type_dict["int"].items()
                    if rtype_int.startswith(reg_type)
                ]
        else:
            return []

    @CLIUtil.addcommand()
    def create_key(self, new_key: str, subkey: str | None = None) -> bool | None:
        """
        Create a new key named as the specified `new_key` under the `subkey`.
        If no subkey is specified, it uses the current subkey path.

        :param new_key: name a the new key to create
        :param subkey: relative subkey to create the the new key

        :return: returns True if all went well, None otherwise.
        """

        # Try to use the cache
        handle = self._get_cached_elt(
            subkey=subkey,
            desired_access=0x4,  # KEY_CREATE_SUB_KEY
        )
        if handle is None:
            logger.error("Could not get handle on the specified subkey.")
            return None

        if subkey is None:
            subkey_path = self._join_path(self.current_subkey_path, new_key)
        else:
            subkey_path = self._join_path(self.current_subkey_path, subkey)
            subkey_path = self._join_path(subkey_path, new_key)

        # Log and send request
        logger.debug("Creating key %s under %s", new_key, subkey_path)

        try:
            self.client.create_subkey(
                self.current_root_handle,
                subkey_path,
                desired_access_rights=self.sam_requested_access_rights,
                options=self.extra_options,
                security_attributes=DEFAULT_SECURITY_DESCRIPTOR,
                timeout=self.timeout,
            )
        except ValueError as resp_exc:
            logger.error("Got status %s while creating key", hex(int(resp_exc.args[0])))
            # We remove the entry from the cache if it exists
            # Even if the response status is not OK, we want to remove it
            if subkey_path.parent in self.cache["ls"]:
                c_elt = self.cache["ls"].pop(subkey_path.parent, None)
                if c_elt is not None:
                    self._close_key(c_elt.handle)
            if subkey_path in self.cache["cat"]:
                c_elt = self.cache["cat"].pop(subkey_path, None)
                if c_elt is not None:
                    self._close_key(c_elt.handle)
            return None

        # We remove the entry from the cache if it exists
        if subkey_path.parent in self.cache["ls"]:
            c_elt = self.cache["ls"].pop(subkey_path.parent, None)
            if c_elt is not None:
                self._close_key(c_elt.handle)
        if subkey_path in self.cache["cat"]:
            c_elt = self.cache["cat"].pop(subkey_path, None)
            if c_elt is not None:
                self._close_key(c_elt.handle)

        print(f"Key {new_key} created successfully.")
        return True

    @CLIUtil.addcommand(mono=True)
    def delete_key(self, subkey: str | None = None) -> bool | None:
        """
        Delete the specified subkey. If no subkey is specified,
        it uses the current subkey path.
        Proper same access rights are required to delete a key.
        By default we request MAXIMUM_ALLOWED. So no issue.

        :param subkey: the relative subkey to delete. If None, it uses
            the current subkey path.

        :return: returns True if all went well, None otherwise.
        """

        # Make sure that we have a backup activated
        self.backup(activate=True)

        # Determine the subkey path for logging and cache purposes
        if subkey is None:
            subkey_path = self.current_subkey_path
        else:
            subkey_path = self._join_path(self.current_subkey_path, subkey)

        # Log and prepare request
        logger.debug("Deleting key %s", subkey_path)
        try:
            self.client.delete_subkey(
                self.current_root_handle,
                subkey_path,
                timeout=self.timeout,
            )
        except ValueError as resp_exc:
            logger.error("Got status %s while deleting key", hex(int(resp_exc.args[0])))
            # Even if the response status is not OK, we want to remove it
            # the entry from the cache if it exists
            if subkey_path.parent in self.cache["ls"]:
                c_elt = self.cache["ls"].pop(subkey_path.parent, None)
                if c_elt is not None:
                    self._close_key(c_elt.handle)
            if subkey_path in self.cache["cat"]:
                c_elt = self.cache["cat"].pop(subkey_path, None)
                if c_elt is not None:
                    self._close_key(c_elt.handle)
            return None

        # We remove the entry from the cache if it exists
        # Even if the response status is not OK, we want to remove it
        if subkey_path.parent in self.cache["ls"]:
            c_elt = self.cache["ls"].pop(subkey_path.parent, None)
            if c_elt is not None:
                self._close_key(c_elt.handle)
        if subkey_path in self.cache["cat"]:
            c_elt = self.cache["cat"].pop(subkey_path, None)
            if c_elt is not None:
                self._close_key(c_elt.handle)

        print(f"Key {subkey} deleted successfully.")
        return True

    @CLIUtil.addcomplete(delete_key)
    def delete_key_complete(self, subkey: str) -> list[str]:
        """
        Auto-complete delete_key
        """

        return self.ls_complete(subkey)

    @CLIUtil.addcommand()
    def delete_value(self, value: str = "", subkey: str | None = None) -> bool | None:
        """
        Delete the specified value.
        If no subkey is specified, it uses the current subkey path.
        If no value is specified, it will delete the default value
        of the subkey, but subkey cannot be specified in CLI mode.

        :param value: the value to delete.
        :param subkey: the relative subkey which holds the value to delete.
        If None, it uses the current subkey path.

        :return: returns True if all went well, None otherwise.
        """

        # Try to use the cache
        handle = self._get_cached_elt(
            subkey=subkey, desired_access=0x20006  # KEY_WRITE
        )
        if handle is None:
            logger.error("Could not get handle on the specified subkey.")
            return None

        # Determine the subkey path for logging and cache purposes
        if subkey is None:
            subkey_path = self.current_subkey_path
        else:
            subkey_path = self._join_path(self.current_subkey_path, subkey)

        # Log and prepare request
        logger.debug("Deleting value %s in %s", value, subkey_path)

        try:
            self.client.delete_value(
                handle,
                value,
                timeout=self.timeout,
            )
        except ValueError as resp_exc:
            logger.error(
                "Got status %s while deleting value", hex(int(resp_exc.args[0]))
            )
            # Even if the response status is not OK, we want to remove it
            # the entry from the cache if it exists
            if subkey_path in self.cache["cat"]:
                c_elt = self.cache["cat"].pop(subkey_path, None)
                if c_elt is not None:
                    self._close_key(c_elt.handle)
            return None

        # We remove the entry from the cache if it exists
        if subkey_path in self.cache["cat"]:
            c_elt = self.cache["cat"].pop(subkey_path, None)
            if c_elt is not None:
                self._close_key(c_elt.handle)

        print(f"Value {value} deleted successfully.")
        return True

    @CLIUtil.addcomplete(delete_value)
    def delete_value_complete(self, param_to_complete: list[str]) -> list[str]:
        """
        Auto-complete delete_value
        """
        if self._require_root_handles(silent=True):
            return []

        if len(param_to_complete) == 1:
            value = param_to_complete[0]
            value = value.strip()
            return [
                subval.reg_name.strip("\x00")
                for subval in self.cat()
                if str(subval.reg_name).lower().startswith(value.lower())
            ]
        elif len(param_to_complete) == 2:
            subkey = param_to_complete[1]
            return self.ls_complete(subkey)
        else:
            return []

    # --------------------------------------------- #
    #                   Backup and Restore
    # --------------------------------------------- #

    @CLIUtil.addcommand()
    def save(
        self,
        output_path: str | None = None,
        subkey: str | None = None,
        fsecurity: bool = False,
    ) -> bool | None:
        """
        Backup the current subkey to a file. If no subkey is specified,
        it uses the current subkeypath. If no output_path is specified,
        it will be saved in the `%WINDIR%\\System32` directory with the
        name of the subkey and .reg extension.
        By default it saves the backup to a file protected so that only BA can read it.

        :param output_path: The path to save the backup file. If None, it defaults
                            to the current subkey name with .reg extension.
                            If the output path ends with .reg, it uses it as is,
                            otherwise it appends .reg to the output path.
        :param subkey: the relative subkey to backup. If None, it uses the
                            current subkey path.
        :param fsecurity: do not set security descriptor of the backup. Let it be
                            inherited from its parent folder.

        :return: returns True if all went well, None otherwise.
        """

        # Make sure that we have a backup activated
        self.backup(activate=True)

        # Try to use the cache
        handle = self._get_cached_elt(subkey=subkey)
        key_to_save = (
            subkey.split("\\")[-1] if subkey else self.current_subkey_path.name
        )

        if handle is None:
            logger.error("Could not get handle on the specified subkey.")
            return None

        # Default path is %WINDIR%\System32
        if output_path is None:
            output_path = str(key_to_save) + ".reg"

        elif output_path.endswith(".reg"):
            # If the output path ends with .reg, we use it as is
            output_path = str(self._join_path("", output_path))

        else:
            # Otherwise, we use the current subkey path as the output path
            output_path = str(self._join_path(output_path, str(key_to_save) + ".reg"))

        if fsecurity:
            print(
                "Looks like you don't like security so much. "
                "Hope you know what you are doing."
            )
            logger.warning("Disabling security built-in protections while saving.")
            sa = None
        else:
            sa = PRPC_SECURITY_ATTRIBUTES(
                RpcSecurityDescriptor=RPC_SECURITY_DESCRIPTOR(
                    lpSecurityDescriptor=DEFAULT_SECURITY_DESCRIPTOR,
                ),
                bInheritHandle=False,
                ndr64=True,
            )
            sa.nLength = len(sa)

        # Log and prepare request
        logger.debug("Backing up %s to %s", key_to_save, output_path)
        self.client.save_subkey(
            key_handle=handle,
            file_path=output_path,
            security_attributes=sa,
        )

        logger.info(
            "Backup of %s saved to %s.reg successful ",
            self.current_subkey_path,
            output_path,
        )
        print(f"Backup of {self.current_subkey_path} saved to {output_path}")
        return True

    # --------------------------------------------- #
    #                   Operation options
    # --------------------------------------------- #

    @CLIUtil.addcommand()
    def backup(self, activate: bool = None) -> None:
        """
        Activate / Disable the backup option for the registry operations.
        This enable / disable the backup privilege for the current session
        if the privilege was respectively disabled / enabled.

        :param activate: if set then always end up with an enabled backup privilege.
        """

        # check if backup privilege is already enabled
        if self.extra_options & RegOptions.REG_OPTION_BACKUP_RESTORE and not activate:
            self.extra_options &= ~RegOptions.REG_OPTION_BACKUP_RESTORE
            logger.debug("Backup option disabled")
        else:
            self.extra_options |= RegOptions.REG_OPTION_BACKUP_RESTORE

            # Log and print
            logger.debug("Backup option activated.")
            print("Backup option activated.")

            # Clear the local cache, as the backup option
            # will change the behavior of the registry
            self.clear_all_caches()

    @CLIUtil.addcommand()
    def volatile(self) -> None:
        """
        Set / Unset the registry operations to be volatile.
        This means that the registry key will be deleted when the system is restarted.
        """

        if not (self.extra_options & RegOptions.REG_OPTION_VOLATILE):
            self.extra_options |= RegOptions.REG_OPTION_VOLATILE
            self.extra_options &= ~RegOptions.REG_OPTION_NON_VOLATILE
            self.use(self.current_root_path)

            # Log and print
            logger.debug("Volatile option activated.")
            print("Volatile option activated.")

            self.clear_all_caches()
        else:
            self.extra_options &= ~RegOptions.REG_OPTION_VOLATILE
            self.extra_options |= RegOptions.REG_OPTION_NON_VOLATILE
            self.use(self.current_root_path)

            # Log and print
            logger.debug("Volatile option deactivated.")
            print("Volatile option deactivated.")

            self.clear_all_caches()

    # --------------------------------------------- #
    #                   Utils
    # --------------------------------------------- #

    def get_handle_on_subkey(
        self,
        subkey_path: PureWindowsPath,
        desired_access_rights: IntFlag | None = None,
    ) -> NDRContextHandle | None:
        """
        Ask the remote server to return an handle on a given subkey.
        If no access rights are specified, it defaults to read access rights.

        :param subkey_path: The subkey path to get a handle on.
        :param desired_access_rights: The desired access rights for the
            subkey. If None, defaults to read access rights.

        :return: An NDRContextHandle on success, None on failure.
        """

        # If we don't have a root handle, we cannot get a subkey handle
        # This is a safety check, as we should not be able to call this function
        # without having a root handle already set.
        if self._require_root_handles(silent=True):
            return None

        # If no access rights were specified, we use the default read access rights
        if desired_access_rights is None:
            # Default to read access rights
            desired_access_rights = 0x20019  # KEY_READ | STANDARD_RIGHTS_READ

        try:
            resp_handle = self.client.get_subkey_handle(
                self.current_root_handle,
                subkey_path,
                desired_access_rights=desired_access_rights,
                options=self.extra_options,
                timeout=self.timeout,
            )
        except ValueError as resp_exc:
            logger.error(
                "Got status %s while getting handle on key: %s",
                hex(int(resp_exc.args[0])),
                subkey_path,
            )
            return None

        return resp_handle

    def _get_cached_elt(
        self,
        subkey: str | None = None,
        cache_name: str = None,
        desired_access: IntFlag | None = None,
    ) -> NDRContextHandle | CacheElt | None:
        """
        Get a cached element for the specified subkey.

        If the element is not cached, it retrieves the handle on the subkey
        and caches it for future use.

        :param subkey: The subkey path to retrieve. If None, uses the
            current subkey path.
        :param cache_name: The name of the cache to use. If None, does
            not use cache.
        :param desired_access: The desired access rights for the subkey.
            If None, defaults to read access rights.

        :return: A CacheElt object if cache_name is provided, otherwise
            an NDRContextHandle.
        """

        if self._require_root_handles(silent=True):
            return None

        if desired_access is None:
            # Default to read access rights
            desired_access = 0x20019  # KEY_READ | STANDARD_RIGHTS_READ

        # If no specific subkey was specified
        # we use our current subkey path
        if subkey is None or subkey == "" or subkey == ".":
            subkey_path = self.current_subkey_path

        # Otherwise we use the subkey path,
        # the calling parent shall make sure that this path was properly sanitized
        else:
            subkey_path = self._join_path(self.current_subkey_path, subkey)

        # If cache name is specified, we try to use it
        if (
            self.cache.get(cache_name, None) is not None
            and self.cache[cache_name].get(subkey_path, None) is not None
            and self.cache[cache_name][subkey_path].access == desired_access
        ):
            # If we have a cache, we check if the handle is already cached
            # If the access rights are the same, we return the cached elt
            return self.cache[cache_name][subkey_path]

        # Otherwise, we need to get a new handle on the subkey
        handle = self.get_handle_on_subkey(subkey_path, desired_access)
        if handle is None:
            logger.error("Could not get handle on %s", subkey_path)
            return None

        # If we have a cache name, we store the handle in the cache
        cache_elt = CacheElt(handle, desired_access, [])
        if cache_name is not None:
            self.cache[cache_name][subkey_path] = cache_elt

        return cache_elt if cache_name is not None else handle

    def _join_path(
        self, first_path: str | None, second_path: str | None
    ) -> PureWindowsPath:
        """
        Join two paths in a way that is compatible with Windows paths.
        This ensures that the paths are normalized and combined correctly,
        even if they are provided as strings or PureWindowsPath objects.

        :param first_path: The first path to join.
        :param second_path: The second path to join.

        :return: A PureWindowsPath object representing the combined path.
        """

        if first_path is None:
            first_path = ""
        if second_path is None:
            second_path = ""
        if str(PureWindowsPath(second_path).as_posix()).startswith("/"):
            # If the second path is an absolute path, we return it as is
            return PureWindowsPath(
                os.path.normpath(PureWindowsPath(second_path).as_posix()).lstrip("/")
            )
        return PureWindowsPath(
            os.path.normpath(
                os.path.join(
                    PureWindowsPath(first_path).as_posix(),
                    PureWindowsPath(second_path).as_posix(),
                )
            )
        )

    def _require_root_handles(self, silent: bool = False) -> bool:
        """
        Check if we have a root handle set.

        :param silent: If True, do not print any message if no root handle is set.

        :return: True if no root handle is set, False otherwise.
        """

        if self.current_root_handle is None:
            if not silent:
                print("No root key selected ! Use 'use' to use one.")
            return True
        return False

    def _close_key(self, handle: NDRContextHandle) -> bool | None:

        # Log and close
        logger.debug("Closing hKey %s - %s", handle.uuid, handle.uuid.hex())
        try:
            self.client.close_key(handle, timeout=self.timeout)
        except ValueError as resp_exc:
            logger.error("Got status %s while closing key", hex(int(resp_exc.args[0])))
            return None

        return True

    @CLIUtil.addcommand()
    def clear_all_caches(self) -> None:
        """
        Clear all caches (cat, ls, etc.)
        """

        for _, c in self.cache.items():
            for c_elt in c.values():
                self._close_key(c_elt.handle)
            c.clear()

    @CLIUtil.addcommand()
    def dev(self) -> NoReturn:
        """
        Joker function to jump into the python code for dev purpose
        """

        logger.info("Jumping into the code for dev purpose...")
        # pylint: disable=forgotten-debug-statement, pointless-statement
        # pylint: disable=import-outside-toplevel, unused-import
        from IPython import embed  # noqa: F401

        print("[!] For a better experience type: embed()")
        breakpoint()


def main():
    """
    Main entry point
    """
    from scapy.utils import AutoArgparse

    AutoArgparse(RegClient)


if __name__ == "__main__":
    main()
