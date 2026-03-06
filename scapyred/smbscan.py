# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy RED
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
Scan's SMB servers and return the version of Windows, SMB signing information
and other information.
"""

import time
import socket

from scapy.automaton import ATMT
from scapy.base_classes import Net
from scapy.error import warning
from scapy.layers.netbios import NBTSession
from scapy.layers.ntlm import NTLM_CHALLENGE
from scapy.layers.smb2 import SMB2_Negotiate_Protocol_Response, SMBStreamSocket
from scapy.layers.smbclient import SMB_Client
from scapy.layers.spnego import SPNEGO_negToken
from scapy.utils import pretty_list

from multiprocessing.dummy import Pool


class SCAN_SMB_CLIENT(SMB_Client):
    """
    SMB_Client modified to run a SMB scan
    """

    def __init__(self, *args, **kwargs):
        self.negotiate = None
        self.ntlmchall = None
        super(SCAN_SMB_CLIENT, self).__init__(*args, **kwargs)

    @ATMT.state(final=1)
    def END(self):
        pass

    # We hook the SENT_NEGOTIATE and NEGOTIATED steps to stop
    # as soon as we got the NTLM CHALLENGE response.

    @ATMT.receive_condition(SMB_Client.SENT_NEGOTIATE)
    def receive_negotiate_response(self, pkt):
        self.negotiate = pkt
        super(SCAN_SMB_CLIENT, self).receive_negotiate_response(pkt)

    @ATMT.state()
    def NEGOTIATED(self, ssp_blob=None):
        # Make sure that we abort the NTLM connection before the AUTH.
        res = None
        if ssp_blob:
            if isinstance(ssp_blob, SPNEGO_negToken):
                ssp_blob = ssp_blob.token.responseToken.value
            if isinstance(ssp_blob, NTLM_CHALLENGE):
                res = self.ntlmchall = ssp_blob
        if not res:
            # We don't have anything in here
            return self.session.ssp.GSS_Init_sec_context(
                self.session.sspcontext, ssp_blob
            )
        return (self.session.sspcontext, None, 0)

    @ATMT.condition(NEGOTIATED, prio=0)
    def should_end(self, ssp_tuple):
        if self.ntlmchall:
            raise self.END()


def smb_scan_winver(
    IP: str = "",
    file: str = "",
    port: int = 445,
    pool: int = 10,
    inter: int = 0,
    timeout: float = 0.1,
    csv: bool = False,
):
    """
    Scan Windows machines using smb

    This attempts an NTLM auth and stop after receiving the Chall.
    The challenge contains extra information such as the build version, that
    can be very useful.

    :param IP: if provided, the ip or range to scan. e.g. 192.168.0.0/24
    :param file: if provided, a file containing the list of ips
    :param port: the port to use
    :param timeout: connect timeout
    :param pool: number of threads in the thread pool
    :param inter: inter time to wait before the next packet (per thread)
    :param csv: output in CSV format instead of a table and remove logs
    """
    assert IP or file, "Must provide 'IP' or 'file'"
    if IP:
        ips = Net(IP)
    else:
        with open(file) as fd:
            ips = [x.strip() for x in fd]

    pool = Pool(pool)

    def resolv(ip):
        if not csv:
            print(f"Scanning {ip}...")
        sock = socket.socket()
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
        except OSError:
            return
        cli_atmt = SCAN_SMB_CLIENT(SMBStreamSocket(sock, NBTSession), guest=True)
        cli_atmt.run()
        sock.close()
        cli_atmt.stop()
        cli_atmt.destroy()
        # Get results
        nego = cli_atmt.negotiate
        tok = cli_atmt.ntlmchall
        if not tok or not nego:
            # No result
            return
        data = [
            ip,
        ]
        if SMB2_Negotiate_Protocol_Response in nego:
            if nego[SMB2_Negotiate_Protocol_Response].SecurityMode.SIGNING_REQUIRED:
                data.append("YES")
            else:
                data.append("NO")
        else:
            data.append("")
        if hasattr(tok, "TargetInfo"):
            values = {x.sprintf("%AvId%"): x.sprintf("%Value%") for x in tok.TargetInfo}
            data.extend(
                [
                    "%s.%s" % (tok.ProductMajorVersion, tok.ProductMinorVersion),
                    str(tok.ProductBuild),
                    values.get("MsvAvNbDomainName", ""),
                    values.get("MsvAvNbComputerName", ""),
                    values.get("MsvAvDnsDomainName", ""),
                    values.get("MsvAvDnsComputerName", ""),
                    values.get("MsvAvTimestamp", ""),
                ]
            )
        else:
            data.extend([""] * 7)
        # Wait
        if inter:
            time.sleep(inter)
        return tuple(data)

    def resolv_ign(ip):
        try:
            return resolv(ip)
        except Exception as ex:
            warning(str(ex))

    headers = (
        "IP",
        "REQUIRE_SIGNATURE",
        "WinVer",
        "Product Build",
        "Domain name",
        "Computer Name",
        "DNS domain name",
        "DNS computer name",
        "Timestamp",
    )
    results = []
    try:
        for x in pool.map(resolv_ign, ips):
            if not x:
                continue
            results.append(x)
    except KeyboardInterrupt:
        pass
    if csv:
        for res in results:
            print(",".join(res))
    else:
        print(pretty_list(results, [headers], borders=True))


def main():
    """
    Main entry point
    """
    from scapy.utils import AutoArgparse

    conf.exts.load("scapy-red")
    AutoArgparse(smb_scan_winver)


# For autocompletion generation
AUTOCOMPLETE_GEN = smb_scan_winver

if __name__ == "__main__":
    main()
