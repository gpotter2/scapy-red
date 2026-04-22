# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy RED
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
LSA remote manager - Manage local SID rights
"""

from scapy.config import conf

conf.exts.load("scapy-rpc")

from scapy.layers.spnego import SPNEGOSSP
from scapy.layers.dcerpc import DCERPC_Transport, find_dcerpc_interface
from scapy.layers.msrpce.rpcclient import DCERPC_Client

from scapy.layers.windows.security import WINNT_SID

from scapy.layers.msrpce.raw.ms_lsad import (
    LsarAddAccountRights_Request,
    LsarAddAccountRights_Response,
    LsarClose_Request,
    LsarEnumerateAccountsWithUserRight_Request,
    LsarEnumerateAccountsWithUserRight_Response,
    LsarOpenPolicy2_Request,
    LsarRemoveAccountRights_Request,
    LsarRemoveAccountRights_Response,
    PLSAPR_USER_RIGHT_SET,
    PRPC_SID,
    PRPC_UNICODE_STRING,
)
from scapy.layers.msrpce.raw.ms_eerr import *

LSAD_MAXIMUM_ALLOWED = 0x02000000
LSAD_RIGHTS = [
    "SeNetworkLogonRight",
    "SeMachineAccountPrivilege",
    "SeBackupPrivilege",
    "SeChangeNotifyPrivilege",
    "SeSystemtimePrivilege",
    "SeCreatePagefilePrivilege",
    "SeDebugPrivilege",
    "SeRemoteShutdownPrivilege",
    "SeAuditPrivilege",
    "SeIncreaseQuotaPrivilege",
    "SeIncreaseBasePriorityPrivilege",
    "SeLoadDriverPrivilege",
    "SeBatchLogonRight",
    "SeServiceLogonRight",
    "SeInteractiveLogonRight",
    "SeSecurityPrivilege",
    "SeSystemEnvironmentPrivilege",
    "SeProfileSingleProcessPrivilege",
    "SeSystemProfilePrivilege",
    "SeAssignPrimaryTokenPrivilege",
    "SeRestorePrivilege",
    "SeShutdownPrivilege",
    "SeTakeOwnershipPrivilege",
    "SeUndockPrivilege",
    "SeEnableDelegationPrivilege",
    "SeManageVolumePrivilege",
    "SeRemoteInteractiveLogonRight",
    "SeImpersonatePrivilege",
    "SeCreateGlobalPrivilege",
    "SeIncreaseWorkingSetPrivilege",
    "SeTimeZonePrivilege",
    "SeCreateSymbolicLinkPrivilege",
    "SeDelegateSessionUserImpersonatePrivilege",
]


def lsamgr(
    target: str,
    action: str,
    UPN: str = None,
    password: str = None,
    HashNt: bytes = None,
    HashAes256Sha96: bytes = None,
    HashAes128Sha96: bytes = None,
    kerberos_required: bool = False,
    ccache: str = None,
    debug: int = 0,
    right: str = None,
    sid: str = None,
    use_krb5ccname: bool = False,
    ssp=None,
):
    r"""
    LSA remote manager.

    :param target: can be a hostname, the IPv4 or the IPv6 to connect to
    :param action: either 'enumerate', 'add' or 'delete'
    :param UPN: the upn to use (DOMAIN/USER, DOMAIN\USER, USER@DOMAIN or USER)
    :param ssp: if provided, use this SSP for auth.
    :param kerberos_required: require kerberos
    :param password: if provided, used for auth
    :param HashNt: if provided, used for auth (NTLM)
    :param HashAes256Sha96: if provided, used for auth (Kerberos)
    :param HashAes128Sha96: if provided, used for auth (Kerberos)
    """

    if action not in ["enumerate", "add", "delete"]:
        raise ValueError("Invalid action !")

    if ssp is None:
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

    # Establish connection
    client = DCERPC_Client(
        DCERPC_Transport.NCACN_NP,
        ssp=ssp,
    )
    client.connect(target, smb_kwargs={"debug": debug})
    client.open_smbpipe("lsarpc")
    client.bind(find_dcerpc_interface("lsarpc"))

    # Open local policy with maximum access
    pkt = LsarOpenPolicy2_Request(
        SystemName=None,
        DesiredAccess=LSAD_MAXIMUM_ALLOWED,
    )
    res = client.sr1_req(pkt)
    policyHandle = res.PolicyHandle

    if action == "enumerate":
        #############
        # ENUMERATE #
        #############

        results_rights = []
        for right in LSAD_RIGHTS:
            # Get the SIDs that have this right
            pkt = LsarEnumerateAccountsWithUserRight_Request(
                PolicyHandle=policyHandle,
                UserRight=PRPC_UNICODE_STRING(
                    Buffer=right,
                ),
            )

            res = client.sr1_req(pkt)
            if (
                LsarEnumerateAccountsWithUserRight_Response not in res
                or res.status not in [0, 0x8000001A]
            ):
                print("Failed :(")
                res.show()
                return

            results = []
            if res.status != 0x8000001A:  # STATUS_NO_MORE_ENTRIES
                for entry in res.valueof("EnumerationBuffer.Information"):
                    sid = WINNT_SID(bytes(entry.valueof("Sid")))
                    results.append(sid.summary())

            results_rights.append((right, results))

        # Show results
        for right, results in results_rights:
            print("%s:" % right)
            for res in results:
                print(f" - {res}")

    elif action == "add":
        #######
        # ADD #
        #######

        pkt = LsarAddAccountRights_Request(
            PolicyHandle=policyHandle,
            AccountSid=PRPC_SID(bytes(WINNT_SID.fromstr(sid))),
            UserRights=PLSAPR_USER_RIGHT_SET(
                UserRights=[PRPC_UNICODE_STRING(Buffer=right)]
            ),
        )

        res = client.sr1_req(pkt)
        if LsarAddAccountRights_Response not in res or res.status != 0:
            return
        res.show()

    elif action == "delete":
        ##########
        # DELETE #
        ##########

        pkt = LsarRemoveAccountRights_Request(
            PolicyHandle=policyHandle,
            AccountSid=PRPC_SID(bytes(WINNT_SID.fromstr(sid))),
            UserRights=PLSAPR_USER_RIGHT_SET(
                UserRights=[PRPC_UNICODE_STRING(Buffer=right)]
            ),
        )
        pkt.show2()

        res = client.sr1_req(pkt)
        if LsarRemoveAccountRights_Response not in res or res.status != 0:
            return
        res.show()

    client.sr1_req(LsarClose_Request(ObjectHandle=policyHandle))


def main():
    """
    Main entry point
    """
    from scapy.utils import AutoArgparse

    conf.exts.load("scapy-red")
    AutoArgparse(lsamgr)


# For autocompletion generation
AUTOCOMPLETE_GEN = lsamgr

if __name__ == "__main__":
    main()
