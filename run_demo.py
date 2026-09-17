#!/usr/bin/env python3
"""Run the three Mininet experiments and produce verified local evidence."""
import argparse
import datetime
import html
import json
import os
import sys
import time
from pathlib import Path

from lab.evaluate import evaluate, read_pcap

ROOT = Path(__file__).resolve().parent


def write_report(run, results):
    rows = []
    details = []
    for result in results:
        scenario = result["scenario"]
        rows.append(f"| {scenario} | {'PASS' if result['passed'] else 'FAIL'} | {result['captured_tcp_packets']} | {result['repeated_pure_ack_observations']} |")
        checks = "".join(f"<li>{'PASS' if ok else 'FAIL'} — {html.escape(name)}</li>" for name, ok in result["checks"].items())
        packets = list(read_pcap(run / scenario / "traffic.pcap"))
        start = packets[0][0] if packets else 0
        packet_rows = "".join(
            f"<tr><td>{timestamp-start:.4f}</td><td>{p.src}:{p.sport} → {p.dst}:{p.dport}</td>"
            f"<td>{p.seq}</td><td>{p.ack}</td><td>0x{p.flags:02x}</td><td>{html.escape(repr(p.payload))}</td></tr>"
            for timestamp, p in packets[:200])
        details.append(f"<section><h2>{scenario}: {'PASS' if result['passed'] else 'FAIL'}</h2><ul>{checks}</ul>"
                       f'<p><a href="{scenario}/traffic.pcap">Packet capture</a> · '
                       f'<a href="{scenario}/server.jsonl">Server log</a> · '
                       f'<a href="{scenario}/client.jsonl">Client log</a> · '
                       f'<a href="{scenario}/attacker.jsonl">Attacker log</a></p>'
                       f"<details><summary>Captured TCP packets (first 200)</summary><div class=scroll><table>"
                       f"<tr><th>Seconds</th><th>Direction</th><th>SEQ</th><th>ACK</th><th>Flags</th><th>Payload</th></tr>{packet_rows}</table></div></details></section>")
    (run / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    (run / "REPORT.md").write_text(
        "# TCP session hijacking — measured results\n\n"
        "| Scenario | Result | TCP packets | Repeated pure ACK observations |\n|---|---|---|---|\n" + "\n".join(rows)
        + "\n\nSee results.json for each assertion and report.html for the packet table.\n"
        "Repeated ACK observations alone do not establish an ACK storm. The protected scenario authenticates commands, but TCP disruption remains possible.\n")
    (run / "report.html").write_text(
        "<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
        "<title>CSE 406 — TCP session hijacking results</title><style>"
        "body{font:16px system-ui;max-width:1100px;margin:40px auto;padding:0 20px;background:#f5f7fb;color:#172338}"
        "section{background:white;padding:24px;margin:20px 0;border:1px solid #cad4e0;border-radius:12px}"
        "li{margin:8px 0}table{border-collapse:collapse;font:13px monospace}td,th{padding:8px;border:1px solid #ddd;text-align:left;white-space:nowrap}"
        ".scroll{overflow:auto}a{color:#075aa5}</style><h1>TCP session hijacking</h1>"
        "<p>Measured results from the Mininet client/attacker/server lab, one flat hub-connected segment. "
        "Packet packing, capture, and checksums use original Python code.</p>"
        + "".join(details) + "<p>The protected scenario checks command integrity and replay counters. It does not prevent transport disruption. "
        "Repeated ACK observations are evidence to inspect, not a guarantee of an ACK storm.</p></html>")


def tail_events(path, timeout, matches):
    """Poll a role's JSONL evidence file until an event satisfying `matches` appears."""
    deadline = time.monotonic() + timeout
    seen = 0
    while time.monotonic() < deadline:
        if path.exists():
            lines = path.read_text().splitlines()
            for line in lines[seen:]:
                seen += 1
                if line.strip() and matches(json.loads(line)):
                    return True
        time.sleep(0.05)
    return False


def run_scenario(scenario, run):
    from lab.mininet_topo import build_net

    directory = run / scenario
    directory.mkdir()
    env = dict(os.environ, SCENARIO=scenario, EVIDENCE_DIR=str(run),
               PYTHONPATH=str(ROOT), PYTHONUNBUFFERED="1")
    net, client, attacker, server = build_net()
    net.start()
    attacker_proc = server_proc = None
    try:
        attacker_proc = attacker.popen(["python3", "-m", "lab.attacker"], cwd=str(ROOT), env=env)
        if not tail_events(directory / "attacker.jsonl", 10, lambda e: e["event"] == "ready"):
            raise RuntimeError("attacker did not become ready in time")
        server_proc = server.popen(["python3", "-m", "lab.server"], cwd=str(ROOT), env=env)
        if not tail_events(directory / "server.jsonl", 10, lambda e: e["event"] == "listening"):
            raise RuntimeError("server did not become ready in time")
        client_proc = client.popen(["python3", "-m", "lab.client"], cwd=str(ROOT), env=env)
        if client_proc.wait(timeout=35) != 0:
            raise RuntimeError("client exited with an error, see " + str(directory / "client.jsonl"))
    finally:
        for proc in (attacker_proc, server_proc):
            if proc is not None:
                proc.terminate()
        for proc in (attacker_proc, server_proc):
            if proc is not None:
                try:
                    proc.wait(timeout=5)
                except Exception:
                    proc.kill()
        net.stop()
    return evaluate(directory, scenario)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=("all", "baseline", "attack", "protected"), default="all")
    parser.add_argument("--sudo", action="store_true", help="Re-exec under sudo (Mininet needs root)")
    args = parser.parse_args()

    if args.sudo and os.geteuid() != 0:
        os.execvp("sudo", ["sudo", "-E", sys.executable, str(Path(__file__).resolve()),
                            *[a for a in sys.argv[1:] if a != "--sudo"]])
    if os.geteuid() != 0:
        print("Mininet needs root privileges. Run: sudo python3 run_demo.py, "
              "or python3 run_demo.py --sudo", file=sys.stderr)
        return 1

    try:
        from mininet.log import setLogLevel
        from mininet.clean import cleanup as mininet_cleanup
    except ImportError:
        print("Mininet is not installed. Install it (e.g. `sudo apt install mininet` "
              "or the official install.sh) and make sure Open vSwitch is running.", file=sys.stderr)
        return 1

    setLogLevel("warning")
    mininet_cleanup()  # clear any interfaces/bridges left over from a crashed prior run

    run = ROOT / "evidence" / datetime.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    run.mkdir(parents=True)
    scenarios = ("baseline", "attack", "protected") if args.scenario == "all" else (args.scenario,)
    results = []
    try:
        for scenario in scenarios:
            print(f"\nRunning {scenario} ...", flush=True)
            results.append(run_scenario(scenario, run))
            write_report(run, results)
            print(f"{scenario}: {'PASS' if results[-1]['passed'] else 'FAIL'}", flush=True)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Demo failed: {exc}\nInspect evidence in {run}", file=sys.stderr)
        return 1
    finally:
        mininet_cleanup()
    print(f"\nReport: {run / 'report.html'}\nChecks: {run / 'results.json'}")
    return 0 if all(result["passed"] for result in results) else 1


if __name__ == "__main__":
    sys.exit(main())
