#!/usr/bin/env python3
"""
NIDS Alert Monitor + Automated Response
=======================================
Tails Suricata's eve.json, prints alerts in real time, keeps statistics, and
(optionally) blocks source IPs that cross a threshold using the host firewall.

This is the "response mechanism" part of a NIDS: detection alone is not enough,
you also need to react to intrusions.

Usage:
    # follow live alerts (read-only, safe)
    python3 monitor.py --eve /var/log/suricata/eve.json

    # replay a sample file to see how it works, no Suricata needed
    python3 monitor.py --eve ../sample/eve.sample.json --replay

    # enable automatic blocking after 3 alerts from the same IP (needs root)
    sudo python3 monitor.py --eve /var/log/suricata/eve.json --block --threshold 3

Blocking uses iptables on Linux; on other systems it logs what it *would* do.
Never enable --block on a network you don't administer.
"""
import argparse
import json
import os
import platform
import subprocess
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime

C = {"red": "\033[91m", "yel": "\033[93m", "grn": "\033[92m",
     "cyn": "\033[96m", "dim": "\033[90m", "rst": "\033[0m"}
if not sys.stdout.isatty():
    C = {k: "" for k in C}

SEVERITY_LABEL = {1: "HIGH", 2: "MEDIUM", 3: "LOW"}
SEVERITY_COLOR = {1: C["red"], 2: C["yel"], 3: C["cyn"]}


class Responder:
    """Blocks IPs via the OS firewall, once per IP, with an allowlist."""
    def __init__(self, enabled, threshold, allowlist):
        self.enabled = enabled
        self.threshold = threshold
        self.allowlist = set(allowlist)
        self.blocked = set()
        self.hits = Counter()

    def record(self, src_ip):
        if not src_ip or src_ip in self.allowlist:
            return
        self.hits[src_ip] += 1
        if self.hits[src_ip] >= self.threshold and src_ip not in self.blocked:
            self.block(src_ip)

    def block(self, ip):
        self.blocked.add(ip)
        if not self.enabled:
            print(f"{C['dim']}   [response] would block {ip} "
                  f"(run with --block and root to enforce){C['rst']}")
            return
        if platform.system() == "Linux":
            try:
                subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                               check=True, capture_output=True)
                print(f"{C['red']}   [response] BLOCKED {ip} via iptables{C['rst']}")
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                print(f"{C['yel']}   [response] block failed for {ip}: {e}{C['rst']}")
        else:
            print(f"{C['yel']}   [response] blocking only implemented on Linux; "
                  f"would drop {ip}{C['rst']}")


def follow(path, replay):
    """Yield JSON objects from eve.json, tailing the file if not in replay mode."""
    while not os.path.exists(path):
        print(f"Waiting for {path} ...")
        time.sleep(2)
    with open(path) as f:
        if not replay:
            f.seek(0, os.SEEK_END)          # live mode: only new lines
        while True:
            line = f.readline()
            if not line:
                if replay:
                    return                   # end of file in replay mode
                time.sleep(0.4)
                continue
            line = line.strip()
            if line:
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue


def main():
    ap = argparse.ArgumentParser(description="NIDS alert monitor and responder")
    ap.add_argument("--eve", required=True, help="path to Suricata eve.json")
    ap.add_argument("--replay", action="store_true", help="read whole file once, don't tail")
    ap.add_argument("--block", action="store_true", help="actually block IPs (needs root)")
    ap.add_argument("--threshold", type=int, default=3,
                    help="alerts from one IP before blocking (default 3)")
    ap.add_argument("--allow", nargs="*", default=["127.0.0.1"],
                    help="IPs never to block")
    args = ap.parse_args()

    responder = Responder(args.block, args.threshold, args.allow)
    total = 0
    by_sig = Counter()
    by_src = Counter()
    by_sev = Counter()

    print(f"{C['grn']}NIDS monitor started. Watching {args.eve}{C['rst']}")
    print(f"Automatic blocking: {'ON' if args.block else 'off'} "
          f"(threshold {args.threshold})\n")

    try:
        for evt in follow(args.eve, args.replay):
            if evt.get("event_type") != "alert":
                continue
            total += 1
            a = evt["alert"]
            sig = a.get("signature", "unknown")
            sev = a.get("severity", 3)
            src = evt.get("src_ip", "?")
            dst = evt.get("dest_ip", "?")
            dport = evt.get("dest_port", "")
            ts = evt.get("timestamp", "")[:19].replace("T", " ")

            by_sig[sig] += 1
            by_src[src] += 1
            by_sev[SEVERITY_LABEL.get(sev, "LOW")] += 1

            col = SEVERITY_COLOR.get(sev, C["cyn"])
            print(f"{col}[{SEVERITY_LABEL.get(sev,'LOW'):>6}]{C['rst']} {ts}  "
                  f"{src} -> {dst}:{dport}")
            print(f"         {sig}")
            responder.record(src)

    except KeyboardInterrupt:
        pass

    # ---- summary ----
    print("\n" + "=" * 60)
    print(f" ALERT SUMMARY — {total} alerts")
    print("=" * 60)
    print(" By severity:")
    for label in ("HIGH", "MEDIUM", "LOW"):
        if by_sev[label]:
            print(f"   {label:<8} {by_sev[label]}")
    print(" Top signatures:")
    for sig, n in by_sig.most_common(5):
        print(f"   {n:>4}  {sig}")
    print(" Top attackers:")
    for ip, n in by_src.most_common(5):
        flag = " (blocked)" if ip in responder.blocked else ""
        print(f"   {n:>4}  {ip}{flag}")
    if responder.blocked:
        print(f"\n Blocked {len(responder.blocked)} IP(s): "
              f"{', '.join(sorted(responder.blocked))}")


if __name__ == "__main__":
    main()
