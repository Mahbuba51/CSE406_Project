"""Configure container-only host routes using Linux rtnetlink (no ip utility)."""
import errno
import fcntl
import socket
import struct
from .config import *


def interface_for(address):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for _, name in socket.if_nameindex():
            try:
                result = fcntl.ioctl(sock, 0x8915, struct.pack("256s", name.encode()))
                if socket.inet_ntoa(result[20:24]) == address:
                    return name
            except OSError:
                continue
    raise RuntimeError(f"No interface with lab address {address}")


def host_route(destination, gateway, local):
    def attribute(kind, data):
        raw = struct.pack("HH", len(data) + 4, kind) + data
        return raw + b"\0" * (-len(raw) % 4)
    route = struct.pack("BBBBBBBBI", socket.AF_INET, 32, 0, 0, 254, 3, 0, 1, 0)
    route += attribute(1, socket.inet_aton(destination))
    route += attribute(5, socket.inet_aton(gateway))
    route += attribute(4, struct.pack("I", socket.if_nametoindex(interface_for(local))))
    message = struct.pack("IHHII", 16 + len(route), 24, 0x605, 1, 0) + route
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0) as sock:
        sock.settimeout(3)
        sock.bind((0, 0))
        sock.sendto(message, (0, 0))
        response = sock.recv(4096)
        if struct.unpack_from("H", response, 4)[0] != 2:
            raise RuntimeError("Unexpected route acknowledgement")
        error = -struct.unpack_from("i", response, 16)[0]
        if error and error != errno.EEXIST:
            raise OSError(error, "Cannot configure lab route")


def setup(role):
    if role == "client":
        host_route(SERVER_IP, ATTACKER_CLIENT_IP, CLIENT_IP)
    elif role == "server":
        host_route(CLIENT_IP, ATTACKER_SERVER_IP, SERVER_IP)
