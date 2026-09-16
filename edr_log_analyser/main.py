"""
EDR Log Analyser — Entry Point
Parses Windows Security Event Log + Sysmon data, runs 9 mapped to MITRE ATT&CK
detection modules, triages by score and incident chains.
Author: github.com/demonchant
"""
import json, argparse, logging, os
from parser.event_parser import EventParser
from detection.edr_engine import EDREngine
from triage.triage_engine import TriageEngine
from reports.report_generator import ReportGenerator

logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

def run(events_file="data/edr_events.json", output=None):
    print("[*] EDR Log Analyser v1.0")
    events = EventParser().parse(events_file)
    print("[+] " + str(len(events)) + " EDR event(s) parsed.")
    alerts = EDREngine().run(events)
    print("[+] " + str(len(alerts)) + " alert(s) detected.")
    scored_alerts, chains = TriageEngine().prioritise(alerts)
    print("[+] " + str(len(chains)) + " incident chain(s) identified.\n")
    report = ReportGenerator().generate(scored_alerts, chains)
    print(report)
    if output:
        output_dir = os.path.dirname(output)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        with open(output, "w") as f:
            json.dump({"alerts": scored_alerts, "incident_chains": chains}, f, indent=4)
        print("[+] Exported: " + output)

def _configure_console():
    """Keep Unicode reports readable on Windows and redirected terminals."""
    import sys
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


if __name__ == "__main__":
    _configure_console()
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", default="data/edr_events.json")
    ap.add_argument("--output", default="reports/edr_report.json")
    args = ap.parse_args()
    run(args.events, args.output)
