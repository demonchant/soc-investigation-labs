"""
IDS Signature Engine
Matches network packet payloads against a library of detection signatures
using regex pattern matching — similar to Snort/Suricata rule processing.
Detects: web shells, SQL injection, XSS, EternalBlue, DNS tunneling,
PowerShell cradles, Cobalt Strike beacons, PE transfers, path traversal.
Author: github.com/demonchant
"""
import json, argparse, logging, os
from engine.ids_engine import IDSEngine
from reports.report_generator import ReportGenerator

logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

def run(pkts_file="data/network_packets.json",
        sigs_file="signatures/ids_signatures.json", output=None):
    print("[*] IDS Signature Engine v1.0")
    with open(pkts_file) as f: packets = json.load(f)
    with open(sigs_file) as f: sigs = json.load(f)
    print(f"[+] {len(packets)} packets | {len(sigs)} signatures loaded.")
    alerts = IDSEngine(sigs).run(packets)
    c = sum(1 for a in alerts if a["severity"]=="critical")
    print(f"[+] {len(alerts)} alert(s) — {c} Critical.\n")
    report = ReportGenerator().generate(alerts, len(packets), len(sigs))
    print(report)
    if output:
        os.makedirs(os.path.dirname(output), exist_ok=True)
        with open(output,"w") as f: json.dump(alerts, f, indent=4)
        print(f"[+] Exported: {output}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--packets", default="data/network_packets.json")
    ap.add_argument("--sigs", default="signatures/ids_signatures.json")
    ap.add_argument("--output", default="reports/ids_alerts.json")
    args = ap.parse_args()
    run(args.packets, args.sigs, args.output)
