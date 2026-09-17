"""Find a host's own interface by IP, using ioctl (no ip/ifconfig utility)."""
import fcntl
import socket
import struct


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
