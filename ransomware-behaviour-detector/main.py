import json, argparse, logging, os
from detection.ransomware_engine import RansomwareEngine
from reports.report_generator import ReportGenerator
logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

def run(events_file="data/ransomware_events.json", output=None):
    print("[*] Ransomware Behaviour Detector v1.0")
    with open(events_file) as f: events = json.load(f)
    alerts = RansomwareEngine().run(events)
    print("[+] {} alert(s) detected — ALL CRITICAL.".format(len(alerts)))
    print()
    print(ReportGenerator().generate(alerts))
    if output:
        os.makedirs(os.path.dirname(output), exist_ok=True)
        with open(output,"w") as f: json.dump(alerts, f, indent=4)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", default="data/ransomware_events.json")
    ap.add_argument("--output", default="reports/ransomware_alerts.json")
    args = ap.parse_args()
    run(args.events, args.output)
