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
        os.makedirs(os.path.dirname(output), exist_ok=True)
        with open(output,"w") as f: json.dump(alerts, f, indent=4)
        print(f"[+] Exported: {output}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", default="data/ad_events.json")
    ap.add_argument("--output", default="reports/ad_alerts.json")
    args = ap.parse_args()
    run(args.events, args.output)
