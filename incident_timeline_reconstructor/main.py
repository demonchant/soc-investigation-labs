"""
Incident Timeline Reconstructor
Sorts multi-source forensic evidence chronologically, maps to MITRE kill chain
phases, calculates dwell times, identifies patient zero, and produces a
structured incident report for post-incident review and legal handover.
Author: github.com/demonchant
"""
import json, argparse, logging, os
from timeline.reconstructor import TimelineReconstructor
from reports.report_generator import ReportGenerator
logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

def run(evidence_file="data/incident_evidence.json", output=None):
    print("[*] Incident Timeline Reconstructor v1.0")
    with open(evidence_file) as f: evidence = json.load(f)
    print(f"[+] {len(evidence)} evidence item(s) loaded.")
    recon = TimelineReconstructor().reconstruct(evidence)
    print(f"[+] {recon['total_events']} events  |  {len(recon['phases_detected'])} phases  |  {recon['dwell_time_minutes']} min dwell\n")
    report = ReportGenerator().generate(recon)
    print(report)
    if output:
        output_dir = os.path.dirname(output)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        with open(output,"w") as f: json.dump(recon, f, indent=4, default=str)
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
    ap.add_argument("--evidence", default="data/incident_evidence.json")
    ap.add_argument("--output", default="reports/timeline_report.json")
    args = ap.parse_args()
    run(args.evidence, args.output)
