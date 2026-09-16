"""
UEBA - User Behaviour Analytics & Insider Threat Detector
Builds per-user behavioural baselines then detects: off-hours access,
bulk data downloads, USB exfiltration, impossible travel, personal email
data staging, admin privilege abuse, and high-risk country logins.
Author: github.com/demonchant
"""
import json, argparse, logging, os
from profiler.behaviour_profiler import BehaviourProfiler
from detection.ueba_engine import UEBAEngine
from reports.report_generator import ReportGenerator

logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

def run(events_file="data/user_events.json", output=None):
    print("[*] UEBA Insider Threat Detector v1.0")
    with open(events_file) as f: events = json.load(f)
    print(f"[+] {len(events)} user events loaded.")
    profiles = BehaviourProfiler().build(events)
    print(f"[+] Profiles built for {len(profiles)} user(s).")
    alerts = UEBAEngine(profiles).run(events)
    print(f"[+] {len(alerts)} alert(s) detected.\n")
    report = ReportGenerator().generate(alerts, profiles)
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
    ap.add_argument("--events", default="data/user_events.json")
    ap.add_argument("--output", default="reports/ueba_report.json")
    args = ap.parse_args()
    run(args.events, args.output)
