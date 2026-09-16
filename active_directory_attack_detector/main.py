"""
Active Directory Attack Detector
Detects Kerberoasting, DCSync, AS-REP Roasting, Golden Ticket,
privilege escalation, password spraying, and backdoor account creation.
Author: github.com/demonchant
"""
import json, argparse, logging, os
from detection.ad_engine import ADAttackDetector
from reports.report_generator import ReportGenerator
logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

def run(events_file="data/ad_events.json", output=None):
    print("[*] Active Directory Attack Detector v1.0")
    with open(events_file) as f: events = json.load(f)
    print(f"[+] {len(events)} AD event(s) loaded.")
    alerts = ADAttackDetector().run(events)
    print(f"[+] {len(alerts)} alert(s).\n")
    report = ReportGenerator().generate(alerts)
    print(report)
    if output:
        output_dir = os.path.dirname(output)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        with open(output,"w") as f: json.dump(alerts, f, indent=4)
        print(f"[+] Exported: {output}")

def _configure_console():
    """Keep Unicode reports readable on Windows and redirected terminals."""
    import sys
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


if __name__ == "__main__":
    _configure_console()
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", default="data/ad_events.json")
    ap.add_argument("--output", default="reports/ad_alerts.json")
    args = ap.parse_args()
    run(args.events, args.output)
