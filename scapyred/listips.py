# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy RED
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
List the IP addresses of a remote machine using DCE/RPC
"""

import time

from multiprocessing.dummy import Pool

from scapy.config import conf
from scapy.utils import pretty_list
from scapy.error import warning
from scapy.base_classes import Net
from scapy.layers.msrpce.msdcom import DCOM_Client


def listips(
    IP: str = "",
    file: str = "",
    pool: int = 10,
    inter: int = 0,
    timeout: float = 0.1,
    csv: bool = False,
):
    """
    Call the unauthenticated ServerAlive2 RPC (DCOM) to retrieve the list
    of IP addresses.

    :param IP: if provided, the ip or range to scan. e.g. 192.168.0.0/24
    :param file: if provided, a file containing the list of ips
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
        client = DCOM_Client(verb=False)
        try:
            client.connect(ip, timeout=timeout)
        except OSError:
            return None
        # Wait
        if inter:
            time.sleep(inter)
        return [ip, client.ServerAlive2()[0]]

    def resolv_ign(ip):
        try:
            return resolv(ip)
        except Exception as ex:
            warning(str(ex))

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
        print(
            pretty_list(
                results,
                [("Scanned IP", "Other addresses")],
                borders=True,
            )
        )


def main():
    """
    Main entry point
    """
    from scapy.utils import AutoArgparse

    conf.exts.load("scapy-red")
    AutoArgparse(listips)


# For autocompletion generation
AUTOCOMPLETE_GEN = listips

if __name__ == "__main__":
    main()
