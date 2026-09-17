#!/usr/bin/env python3
"""Run the three-container experiments and produce verified local evidence."""
import argparse
import datetime
import html
import json
import os
from pathlib import Path
import subprocess
import sys
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
        "<p>Measured results from the isolated client → attacker/router → server lab. Packet packing, capture, and checksums use original Python code.</p>"
        + "".join(details) + "<p>The protected scenario checks command integrity and replay counters. It does not prevent transport disruption. "
        "Repeated ACK observations are evidence to inspect, not a guarantee of an ACK storm.</p></html>")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=("all", "baseline", "attack", "protected"), default="all")
    parser.add_argument("--sudo", action="store_true", help="Use sudo docker (asks for password in YOUR terminal)")
    parser.add_argument("--no-build", action="store_true", help="Reuse the already-built image")
    args = parser.parse_args()
    docker = (["sudo", "docker"] if args.sudo else ["docker"])
    try:
        subprocess.run(docker + ["info"], check=True, stdout=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError):
        print("Docker is unavailable. Start Docker, or run: python3 run_demo.py --sudo", file=sys.stderr)
        return 1
    run = ROOT / "evidence" / datetime.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    run.mkdir(parents=True)
    scenarios = ("baseline", "attack", "protected") if args.scenario == "all" else (args.scenario,)
    results = []
    env = dict(os.environ, EVIDENCE_ROOT=str(run))

    def compose(*arguments, timeout=120):
        return subprocess.run(docker + ["compose", "-f", str(ROOT / "compose.yaml"), *arguments],
                              cwd=ROOT, env=env, check=True, timeout=timeout)

    try:
        if not args.no_build:
            compose("build", timeout=600)
        for scenario in scenarios:
            env["SCENARIO"] = scenario
            (run / scenario).mkdir()
            compose("down", "--remove-orphans")
            print(f"\nRunning {scenario} ...", flush=True)
            compose("up", "-d", "--wait", "attacker", "server")
            compose("up", "-d", "client")
            compose("wait", "client", timeout=35)
            compose("stop", "-t", "3", "attacker", "server")
            results.append(evaluate(run / scenario, scenario))
            write_report(run, results)
            print(f"{scenario}: {'PASS' if results[-1]['passed'] else 'FAIL'}", flush=True)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"Demo failed: {exc}\nInspect evidence in {run}", file=sys.stderr)
        return 1
    finally:
        try:
            compose("down", "--remove-orphans")
        except subprocess.SubprocessError:
            print("Cleanup failed. Run docker compose down in the project folder.", file=sys.stderr)
    print(f"\nReport: {run / 'report.html'}\nChecks: {run / 'results.json'}")
    return 0 if all(result["passed"] for result in results) else 1


if __name__ == "__main__":
    sys.exit(main())
