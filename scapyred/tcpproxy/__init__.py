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
import mimetypes
import pathlib
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
    REDIRECT_PERMANENT = 2
    REDIRECT_ONCE = 3


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

    def sendEv(self, event) -> None:
        """
        Send an event to the frontend
        """
        self.events.put(event)

    class CONTEXT(ForwardMachine.CONTEXT):
        """
        CONTEXT is created on each TCP session
        """

        def __init__(self, fwdm, addr, dest):
            self.fwdm = fwdm
            self.peer = fwdm.peers[addr[0]]
            self.redirected = False
            super(ProxyFwdMachine.CONTEXT, self).__init__(fwdm, addr, dest)

    def vprint(self, evt, ctx, cs, req, rep):
        """
        This is called by the ForwardMachine on each event.
        """
        src, dst = (repr(ctx.addr), repr(ctx.dest)) if cs else (repr(ctx.dest), repr(ctx.addr))
        ev_type = "client" if cs else "server"

        if evt == self.FORWARD:
            text = f"{src} ==> {dst}: {req.summary()}"
        elif evt == self.FORWARD_REPLACE:
            text = f"{src} /=> {dst}: {req.summary()} -> {rep.summary()}"
        elif evt == self.DROP:
            text = f"{src} => 0: {req.summary()}"
        elif evt == self.ANSWER:
            text = f"{src} <=| : {req.summary()} -> {rep.summary()}"
        elif evt == self.REDIRECT_TO:
            ev_type = "special"
            text = f"{src} was redirected from {repr(req)} to {repr(rep)}"
        elif evt == self.ERROR:
            ev_type = "error"
            text = f"ERROR: {src} {req}"
        else:
            return

        self.sendEv({"type": ev_type, "peer": ctx.addr[0], "text": text})

    def newconn(self, ctx):
        """
        New connection is established
        """
        self.sendEv({"type": "newpeer", "peer": ctx.addr[0]})

    def delconn(self, ctx):
        """
        Connection is deleted.
        """
        self.sendEv({"type": "deadpeer", "peer": ctx.addr[0]})

    def xfrmcs(self, pkt, ctx):
        """
        Client -> Server
        """
        if ctx.peer.state == PeerState.FORWARD:
            raise self.FORWARD()
        elif ctx.peer.state == PeerState.REDIRECT_PERMANENT:
            if ctx.redirected:
                raise self.FORWARD()
            else:
                ctx.redirected = True
                raise self.REDIRECT_TO(host=ctx.peer.redirect_host, port=ctx.peer.redirect_port)
        elif ctx.peer.state == PeerState.REDIRECT_ONCE:
            ctx.redirected = True
            ctx.peer.state = PeerState.FORWARD
            raise self.REDIRECT_TO(host=ctx.peer.redirect_host, port=ctx.peer.redirect_port)
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
        if pkt.Method == b"OPTIONS":
            return HTTPResponse(
                Status_Code=b"200",
                Reason_Phrase=b"OK",
                Access_Control_Allow_Origin="*",
                Access_Control_Allow_Methods="POST, GET, OPTIONS",
                Access_Control_Allow_Headers="*",
            )

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
            # Try to serve a static file from the compiled webapp
            web_dist = pathlib.Path(__file__).parent / "web_dist"
            rel = pkt.Path.lstrip(b"/") or b"index.html"
            try:
                fpath = (web_dist / rel.decode()).resolve()
                # Prevent path traversal outside web_dist
                fpath.relative_to(web_dist.resolve())
                if fpath.is_file():
                    mime = mimetypes.guess_type(str(fpath))[0] or "application/octet-stream"
                    return HTTPResponse(
                        Content_Type=mime,
                        Access_Control_Allow_Origin="*",
                    ) / fpath.read_bytes()
            except (ValueError, UnicodeDecodeError):
                pass
            return HTTPResponse(
                Status_Code=b"404",
                Reason_Phrase=b"Not Found",
            ) / "<!doctype html><html><body><h1>404 - Not Found</h1></body></html>"


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
        verb=False,
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
