"""
Crypto Exchange Security Monitor
Detects: ATO chains, wash trading, API abuse, brute force,
structuring/smurfing, impossible travel, and KYC fraud.
All alerts mapped to MITRE ATT&CK and financial regulations.
Author: github.com/demonchant
"""
import json, argparse, logging, os
from detection.exchange_engine import ExchangeSecurityEngine
from reports.report_generator import ReportGenerator

logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

def run(events_file="data/exchange_events.json", output=None):
    print("[*] Crypto Exchange Security Monitor v1.0")
    with open(events_file) as f:
        events = json.load(f)
    print("[+] Loaded " + str(len(events)) + " exchange events.")
    engine = ExchangeSecurityEngine()
    alerts = engine.run(events)
    print("[+] " + str(len(alerts)) + " alert(s) generated.\n")
    report = ReportGenerator().generate(alerts)
    print(report)
    if output:
        os.makedirs(os.path.dirname(output), exist_ok=True)
        with open(output, "w") as f:
            json.dump(alerts, f, indent=4)
        print("[+] Exported: " + output)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", default="data/exchange_events.json")
    ap.add_argument("--output", default="reports/exchange_alerts.json")
    args = ap.parse_args()
    run(args.events, args.output)
