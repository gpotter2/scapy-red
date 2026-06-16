# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy RED
# See https://scapy.net/ for more information

r"""
A wrapper of Scapy's Forwarding Machine.
"""

import collections
import dataclasses
import enum
import json
import queue
import socket

from scapy.config import conf
from scapy.fwdmachine import ForwardMachine
from scapy.layers.http import (
    HTTP,
    HTTPRequest,
    HTTPResponse,
    HTTP_Server,
)

from typing import Any

############################################
############ Forwarding Machine ############
############################################


class PeerState(enum.IntEnum):
    FORWARD = 1
    REDIRECT_NEXT_CONNECTION = 2
    REDIRECT_NEXT_PACKET = 3


@dataclasses.dataclass
class PEER:
    """
    A PEER is identified by its source IP, and is kept throughout the multiple TCP sessions.
    It is also used to administratively request some actions.
    """

    state: PeerState = PeerState.FORWARD
    redirect_host: str = ""
    redirect_port: int = 0


class ProxyFwdMachine(ForwardMachine):
    """
    Multi-usage Forward Machine
    """

    def __init__(self, *args, **kwargs):
        self.peers: collections.defaultdict[Any, PEER] = collections.defaultdict(PEER)
        self.events = queue.Queue()
        super(ProxyFwdMachine, self).__init__(*args, **kwargs)

    class CONTEXT(ForwardMachine.CONTEXT):
        """
        CONTEXT is created on each TCP session
        """

        def __init__(self, fwdm, addr, dest):
            self.fwdm = fwdm
            self.peer = fwdm.peers[addr[0]]
            self.firstpkt = True
            super(ProxyFwdMachine.CONTEXT, self).__init__(fwdm, addr, dest)

    def xfrmcs(self, pkt, ctx):
        """
        Client -> Server
        """
        if ctx.peer.state == PeerState.REDIRECT_NEXT_CONNECTION and self.firstpkt:
            ctx.peer.state = PeerState.FORWARD
            raise self.REDIRECT_TO(host=self.redirect_host, port=self.redirect_port)
        elif ctx.peer.state == PeerState.REDIRECT_NEXT_PACKET:
            ctx.peer.state = PeerState.FORWARD
            raise self.REDIRECT_TO(host=self.redirect_host, port=self.redirect_port)
        elif ctx.peer.state == PeerState.FORWARD:
            raise self.FORWARD()
        else:
            raise ValueError

    def xfrmsc(self, pkt, ctx):
        """
        Server -> Client
        """
        raise self.FORWARD()


#########################################
############ HTTP management ############
#########################################


class HTTP_Management(HTTP_Server):
    def __init__(self, *args, **kwargs):
        self.fwdm: ProxyFwdMachine = kwargs.pop("fwdm")
        super(HTTP_Management, self).__init__(*args, **kwargs)

    def rep_json(self, data):
        return HTTPResponse(
            Content_Type="application/json",
            Access_Control_Allow_Origin="*",  # ouais.. je sais
            Access_Control_Allow_Headers="*",
        ) / json.dumps(data)

    def answer(self, pkt):
        """
        HTTP_server answer function.

        :param pkt: a HTTPRequest packet
        :returns: a HTTPResponse packet
        """
        if pkt.Path == b"/getpeers" and pkt.Method == b"GET":
            # Get the list of currently connected peers and their status.
            return self.rep_json(
                {
                    k: {
                        "state": int(v.state),
                        "redirection": {
                            "host": v.redirect_host,
                            "port": v.redirect_port,
                        },
                    }
                    for k, v in self.fwdm.peers.items()
                }
            )
        elif pkt.Path == b"/event" and pkt.Method == b"GET":
            # Get a flow of events. The client will poll this on a timer, and immediately
            # whenever an event that isn't 'null' is returned.
            try:
                event = self.fwdm.events.get(timeout=1)
            except queue.Empty:
                event = None
            return self.rep_json(event)
        elif pkt.Path == b"/setpeerstatus" and pkt.Method == b"POST":
            # Set the status of a peer
            try:
                data = json.loads(pkt[HTTPRequest].load)

                ip = data["peer"]  # get the IP address of the peer
                peer = self.fwdm.peers[ip]

                peer.state = data["state"]  # get the state to put the peer into

                if "redirection" in data:
                    peer.redirect_host = data["redirection"]["host"]
                    peer.redirect_port = data["redirection"]["port"]
            except Exception:
                return HTTPResponse(
                    Status_Code=b"400",
                    Reason_Phrase=b"Invalid Request",
                )
        else:
            return HTTPResponse(
                Status_Code=b"404",
                Reason_Phrase=b"Not Found",
            ) / ("<!doctype html><html><body><h1>404 - Not Found</h1></body></html>")


##############################
############ MAIN ############
##############################


class Protos(enum.StrEnum):
    HTTP = "http"
    HTTPS = "https"
    TLS = "tls"
    RAW = "raw"


def tcpproxy(
    *,
    port: int,
    proto: Protos,
    server_mode: bool = False,
    remote_address: str = None,
):
    """
    Start a forwarding machine in TPROXY mode.

    :param port: the port on which to start the machine
    :param proto: the protocol to parse ("http", "https", "tls", "raw")
    :param server_mode: use SERVER mode instead of TPROXY (for debugging)
    :param remote_address: the IP to use in SERVER mode, or by default in TPROXY when
        the destination is the local IP.
    """

    if proto == Protos.HTTP:
        cls = HTTP
        ssl = False
    elif proto == Protos.HTTPS:
        cls = HTTP
        ssl = True
    elif proto == Protos.TLS:
        cls = conf.raw_layer
        ssl = True
    elif proto == Protos.RAW:
        cls = conf.raw_layer
        ssl = False
    else:
        raise ValueError("Unknown 'proto' value.")

    # Start the proxy machine
    fwdm = ProxyFwdMachine(
        mode=ForwardMachine.MODE.SERVER if server_mode else ForwardMachine.MODE.TPROXY,
        port=port,
        cls=cls,
        tls=ssl,
        remote_address=remote_address,
    )

    web = HTTP_Management.spawn(
        port=8888,
        local_ip="127.0.0.1",
        fwdm=fwdm,
        bg=True,
        debug=4,
    )

    try:
        fwdm.run()
    except KeyboardInterrupt:
        pass
    finally:
        web.shutdown(socket.SHUT_RDWR)
        web.close()


def main():
    """
    Main entry point
    """
    from scapy.utils import AutoArgparse

    conf.exts.load("scapy-red")
    AutoArgparse(tcpproxy)


# For autocompletion generation
AUTOCOMPLETE_GEN = tcpproxy

if __name__ == "__main__":
    main()
