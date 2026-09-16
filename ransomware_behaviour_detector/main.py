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
        output_dir = os.path.dirname(output)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        with open(output,"w") as f: json.dump(alerts, f, indent=4)

def _configure_console():
    """Keep Unicode reports readable on Windows and redirected terminals."""
    import sys
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


if __name__ == "__main__":
    _configure_console()
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", default="data/ransomware_events.json")
    ap.add_argument("--output", default="reports/ransomware_alerts.json")
    args = ap.parse_args()
    run(args.events, args.output)
