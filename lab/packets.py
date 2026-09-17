"""Original Ethernet/IPv4/TCP parsing and packing, using only the stdlib."""
import socket
import struct
from dataclasses import dataclass


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


@dataclass(frozen=True)
class Segment:
    src: str
    dst: str
    sport: int
    dport: int
    seq: int
    ack: int
    flags: int
    window: int
    payload: bytes
    options: bytes

    @property
    def next_seq(self):
        return (self.seq + len(self.payload) + bool(self.flags & 2)
                + bool(self.flags & 1)) & 0xffffffff


def parse_frame(frame):
    """Return None for truncated, fragmented, non-IPv4 or non-TCP frames."""
    if len(frame) < 14:
        return None
    ether_type = struct.unpack_from("!H", frame, 12)[0]
    offset = 14
    while ether_type in (0x8100, 0x88a8):
        if len(frame) < offset + 4:
            return None
        ether_type = struct.unpack_from("!H", frame, offset + 2)[0]
        offset += 4
    if ether_type != 0x0800 or len(frame) < offset + 20:
        return None
    ip = frame[offset:]
    ihl = (ip[0] & 15) * 4
    total = struct.unpack_from("!H", ip, 2)[0]
    fragment = struct.unpack_from("!H", ip, 6)[0]
    if (ip[0] >> 4 != 4 or ihl < 20 or total < ihl + 20
            or len(ip) < total or ip[9] != 6 or fragment & 0x3fff):
        return None
    tcp = ip[ihl:total]
    hlen = (tcp[12] >> 4) * 4
    if hlen < 20 or hlen > len(tcp):
        return None
    sport, dport, seq, ack = struct.unpack_from("!HHII", tcp)
    return Segment(socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20]),
                   sport, dport, seq, ack, tcp[13],
                   struct.unpack_from("!H", tcp, 14)[0], tcp[hlen:], tcp[20:hlen])


def timestamps(options):
    pos = 0
    while pos < len(options):
        kind = options[pos]
        if kind == 0:
            break
        if kind == 1:
            pos += 1
            continue
        if pos + 2 > len(options):
            break
        size = options[pos + 1]
        if size < 2 or pos + size > len(options):
            break
        if kind == 8 and size == 10:
            return struct.unpack_from("!II", options, pos + 2)
        pos += size
    return None


def craft_packet(src, dst, sport, dport, seq, ack, window, payload,
                 options=b"", identification=0x406):
    """Build every IPv4/TCP header field, including the TCP pseudo-header checksum."""
    options += b"\x01" * (-len(options) % 4)
    if len(options) > 40 or len(payload) + len(options) > 65495:
        raise ValueError("Packet too large")
    source, destination = socket.inet_aton(src), socket.inet_aton(dst)
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xffffffff,
                      ack & 0xffffffff, ((20 + len(options)) // 4) << 4,
                      0x18, window, 0, 0) + options + payload
    pseudo = source + destination + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), identification,
                     0x4000, 64, 6, 0, source, destination)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return ip + tcp
