"""Mininet topology: one flat, hub-connected segment for client/attacker/server.

A learning switch would only forward each unicast frame to the port whose MAC
it belongs to, which would hide the client<->server traffic from the attacker's
port. A hub instead floods every frame to every port, so the attacker's NIC
sees the live session by simply listening (promiscuous capture), without ever
being in the forwarding path -- this is what the design report's "shared
switch + promiscuous mode" description assumes.
"""
from mininet.net import Mininet
from mininet.node import OVSBridge

from .config import ATTACKER_IP, CLIENT_IP, SERVER_IP


class Hub(OVSBridge):
    """An OVSBridge with a single catch-all flow that floods instead of learns."""

    def start(self, controllers):
        super().start(controllers)
        self.dpctl("add-flow", "actions=flood")


def build_net():
    net = Mininet(controller=None)
    hub = net.addSwitch("hub0", cls=Hub)
    client = net.addHost("client", ip=f"{CLIENT_IP}/24")
    attacker = net.addHost("attacker", ip=f"{ATTACKER_IP}/24")
    server = net.addHost("server", ip=f"{SERVER_IP}/24")
    for host in (client, attacker, server):
        net.addLink(host, hub)
    return net, client, attacker, server
