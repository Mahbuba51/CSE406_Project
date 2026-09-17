"""Validate demo evidence instead of assuming that sending means success."""
import json
import socket
import struct
from collections import Counter
from pathlib import Path
from .config import CLIENT_IP, SERVER_IP, PORT, PAYLOAD
from .packets import checksum, parse_frame


def events(directory, role):
    with (Path(directory) / f"{role}.jsonl").open() as source:
        return [json.loads(line) for line in source if line.strip()]


def read_pcap(path):
    with Path(path).open("rb") as source:
        header = source.read(24)
        if len(header) != 24 or struct.unpack("<IHHIIII", header) != (0xa1b2c3d4, 2, 4, 0, 0, 65535, 1):
            raise ValueError("Unsupported PCAP header")
        while raw := source.read(16):
            if len(raw) != 16:
                raise ValueError("Truncated PCAP record")
            seconds, micros, size, original = struct.unpack("<IIII", raw)
            if size > 65535 or size != original:
                raise ValueError("Invalid captured length")
            frame = source.read(size)
            if len(frame) != size:
                raise ValueError("Truncated PCAP frame")
            segment = parse_frame(frame)
            if segment:
                yield seconds + micros / 1e6, segment


def evaluate(directory, scenario):
    directory = Path(directory)
    server, client, attacker = [events(directory, role) for role in ("server", "client", "attacker")]
    packets = list(read_pcap(directory / "traffic.pcap"))
    injected = [e for e in attacker if e["event"] == "injected"]
    wipes = [e for e in server if e["event"] == "command" and e["command"] == "ADMIN_WIPE"]
    checks = {
        "capture contains TCP traffic": bool(packets),
        "victim never sent ADMIN_WIPE": not any(e.get("command") == "ADMIN_WIPE" for e in client),
        "initial legitimate STATUS processed": any(e.get("command") == "STATUS" and e.get("records") == 3 for e in server),
        "client finished": any(e["event"] == "finished" for e in client),
    }
    if scenario == "baseline":
        checks.update({
            "no injection": not injected,
            "no wipe": not wipes,
            "three correct replies": sum(e["event"] == "reply" and e["matches_expected"] for e in client) == 3,
        })
    else:
        checks["exactly one injected packet"] = len(injected) == 1
        if len(injected) == 1:
            injection = injected[0]
            raw = (directory / "forged-ip-packet.bin").read_bytes()
            ihl = (raw[0] & 15) * 4
            tcp = raw[ihl:]
            pseudo = socket.inet_aton(CLIENT_IP) + socket.inet_aton(SERVER_IP) + struct.pack("!BBH", 0, 6, len(tcp))
            checks["crafted IPv4 checksum valid"] = checksum(raw[:ihl]) == 0
            checks["crafted TCP checksum valid"] = checksum(pseudo + tcp) == 0
            checks["forgery visible in capture"] = any(
                p.src == CLIENT_IP and p.dst == SERVER_IP and p.sport == injection["sport"]
                and p.dport == PORT and p.seq == injection["seq"] and p.payload == PAYLOAD
                for _, p in packets)
            checks["server ACK confirms injected bytes"] = any(
                p.src == SERVER_IP and p.dst == CLIENT_IP and p.dport == injection["sport"]
                and p.ack == (injection["seq"] + len(PAYLOAD)) & 0xffffffff
                for _, p in packets)
        if scenario == "attack":
            checks["server executed spoofed command"] = any(e["peer_ip"] == CLIENT_IP and e["records"] == 0 for e in wipes)
            checks["victim session disrupted"] = any(e["event"] == "disrupted" for e in client)
        else:
            checks["unauthenticated command rejected"] = any(
                e["event"] == "rejected" and e["wire"] == "ADMIN_WIPE" and e["records"] == 3 for e in server)
            checks["no wipe executed"] = not wipes
    acks = Counter((p.src, p.sport, p.dst, p.dport, p.seq, p.ack)
                   for _, p in packets if p.flags == 0x10 and not p.payload)
    return {"scenario": scenario, "passed": all(checks.values()), "checks": checks,
            "captured_tcp_packets": len(packets),
            "repeated_pure_ack_observations": sum(n - 1 for n in acks.values()),
            "injections": len(injected)}
