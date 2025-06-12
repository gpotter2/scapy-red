# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy RED
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
Get unauthenticated information about a domain by querying the rootDSE LDAP.
"""

import socket
import re

from scapy.compat import hex_bytes
from scapy.config import conf
from scapy.utils import pretty_list
from scapy.supersocket import SimpleSocket
from scapy.layers.ldap import (
    LDAP,
    LDAP_Filter,
    LDAP_SearchRequest,
    LDAP_FilterEqual,
    LDAP_FilterAnd,
    LDAP_SearchRequestAttribute,
    LDAP_Control,
    NETLOGON_SAM_LOGON_RESPONSE_EX,
    dclocator,
)
from scapy.asn1.asn1 import ASN1_STRING
from scapy.layers.msrpce.mspac import WINNT_SID

FUNCTIONAL = {
    0: "DS_BEHAVIOR_WIN2000",
    1: "DS_BEHAVIOR_WIN2003_WITH_MIXED_DOMAINS",
    2: "DS_BEHAVIOR_WIN2003",
    3: "DS_BEHAVIOR_WIN2008",
    4: "DS_BEHAVIOR_WIN2008R2",
    5: "DS_BEHAVIOR_WIN2012",
    6: "DS_BEHAVIOR_WIN2012R2",
    7: "DS_BEHAVIOR_WIN2016",
    10: "DS_BEHAVIOR_WIN2025",
}


def dominfo(realm: str, timeout: int = 3):
    """
    Get interesting domain information as unauthenticated
    """
    # IP
    ip = dclocator(realm).ip
    # Open LDAP connection (TCP)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((ip, 389))
    sock = SimpleSocket(sock, LDAP)
    pkt = sock.sr1(
        LDAP(
            protocolOp=LDAP_SearchRequest(
                filter=LDAP_Filter(
                    filter=LDAP_FilterAnd(
                        vals=[
                            LDAP_Filter(
                                filter=LDAP_FilterEqual(
                                    attributeType=ASN1_STRING(b"DnsDomain"),
                                    attributeValue=ASN1_STRING(realm),
                                )
                            ),
                            LDAP_Filter(
                                filter=LDAP_FilterEqual(
                                    attributeType=ASN1_STRING(b"NtVer"),
                                    attributeValue=ASN1_STRING(b"\x16\x00\x00!"),
                                )
                            ),
                        ]
                    )
                ),
                attributes=[
                    LDAP_SearchRequestAttribute(type=ASN1_STRING(x))
                    for x in [
                        # Below is the entire list. Although most of them are not
                        # interesting or are not implemented
                        b"Netlogon",  # KEEP
                        # b"configurationNamingContext ",
                        b"currentTime",  # KEEP
                        # b"defaultNamingContext",
                        # b"dNSHostName",
                        # b"dsSchemaAttrCount",
                        # b"dsSchemaClassCount",
                        # b"dsSchemaPrefixCount",
                        b"dsServiceName",  # KEEP
                        # b"highestCommittedUSN",
                        b"isGlobalCatalogReady",  # KEEP
                        # b"isSynchronized",
                        b"ldapServiceName",  # KEEP
                        # b"namingContexts",
                        b"netlogon",  # KEEP
                        # b"pendingPropagations",
                        b"rootDomainNamingContext",  # KEEP
                        # b"schemaNamingContext",
                        b"serverName",  # KEEP
                        # b"subschemaSubentry",
                        # b"supportedCapabilities",
                        # b"supportedControl",
                        # b"supportedLDAPPolicies",
                        # b"supportedLDAPVersion",
                        b"supportedSASLMechanisms",  # KEEP
                        b"domainControllerFunctionality",  # KEEP
                        b"domainFunctionality",  # KEEP
                        b"forestFunctionality",  # KEEP
                        # b"msDS-ReplAllInboundNeighbors",
                        # b"msDS-ReplAllOutboundNeighbors",
                        # b"msDS-ReplConnectionFailures",
                        # b"msDS-ReplLinkFailures",
                        # b"msDS-ReplPendingOps",
                        # b"msDS-ReplQueueStatistics",
                        # b"msDS-TopQuotaUsage",
                        # b"supportedConfigurableSettings",
                        # b"supportedExtension",
                        # b"validFSMOs",
                        # b"dsaVersio",
                        b"msDS-PortLDAP",  # KEEP
                        b"msDS-PortSSL",  # KEEP
                        b"msDS-PrincipalName",
                        b"serviceAccountInfo",
                        # b"spnRegistrationResult",
                        # b"tokenGroups",
                        # b"usnAtRifmYLargeInteger",
                        # b"approximateHighestInternalObjectID",
                        # b"databaseGuid",
                        # b"schemaIndexUpdateState",
                        # b"dumpLdapNotifications",  # ADMIN REQUIRED
                        # b"msDS-ProcessLinksOperations",
                        # b"msDS-SegmentCacheInfo",
                        # b"msDS-ThreadStates",  # ADMIN REQUIRED
                        b"ConfigurableSettingsEffective",  # KEEP
                        # b"LDAPPoliciesEffective",
                        # b"msDS-ArenaInfo",  # ADMIN REQUIRED
                        # b"msDS-Anchor",
                        # b"msDS-PrefixTable",
                        # b"msDS-SupportedRootDSEAttributes",
                        # b"msDS-SupportedRootDSEModifications",
                    ]
                ],
            ),
            Controls=[
                LDAP_Control(
                    # EXTENDED DN ! This is Magic
                    controlType="1.2.840.113556.1.4.529",
                ),
            ],
        ),
        timeout=timeout,
        verbose=0,
    )
    if pkt:
        # We have a result
        results = []
        for x in pkt[LDAP].protocolOp.attributes:
            typ = x.type.val.decode()
            # Parse the result depending on the type
            if typ.lower() == "netlogon":
                netlogon = NETLOGON_SAM_LOGON_RESPONSE_EX(x.values[0].value.val)
                for fld in [
                    "DnsForestName",
                    "DnsDomainName",
                    "DnsHostName",
                    "NetbiosDomainName",
                    "NetbiosComputerName",
                    "UserName",
                    "DcSiteName",
                    "DcSiteName",
                    "ClientSiteName",
                ]:
                    results.append((fld, netlogon.getfieldval(fld).decode()))
                results.append(("DomainGuid", netlogon.sprintf("%DomainGuid%")))
                continue
            elif typ.lower().endswith("functionality"):
                i = int(x.values[0].value.val)
                results.append((typ, FUNCTIONAL.get(i, str(i))))
            elif typ.lower() == "rootdomainnamingcontext":
                rootDomainNamingContext = x.values[0].value.val
                if m := re.search(b"<SID=([^>]+)>", rootDomainNamingContext):
                    results.append(
                        (
                            "DOMAIN SID",
                            conf.color_theme.yellow(
                                WINNT_SID(hex_bytes(m.group(1))).summary()
                            ),
                        )
                    )
            else:
                results.append((typ, [y.value.val.decode() for y in x.values]))
        print(pretty_list(results, [("Attribute", "Value")]))
    sock.close()


def main():
    """
    Main entry point
    """
    from scapy.utils import AutoArgparse

    AutoArgparse(dominfo)


# For autocompletion generation
AUTOCOMPLETE_GEN = dominfo

if __name__ == "__main__":
    main()
