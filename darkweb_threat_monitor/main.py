"""
Dark Web and Threat Feed Monitor
Processes simulated intelligence from dark web forums, paste sites,
ransomware trackers, certificate transparency logs, and vulnerability feeds.
Scores each item and produces a prioritised response queue.
Author: github.com/demonchant
"""
import json
import argparse
import logging
import os
from analyser.threat_analyser import ThreatAnalyser
from reports.report_generator import ReportGenerator

logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")


def run(feed_file="data/threat_feed.json", output=None):
    print("[*] Dark Web and Threat Feed Monitor v1.0")
    with open(feed_file) as f:
        items = json.load(f)
    print("[+] " + str(len(items)) + " threat intelligence items loaded.")

    results = ThreatAnalyser().analyse(items)
    c = sum(1 for x in results if x["risk_tier"] == "CRITICAL")
    h = sum(1 for x in results if x["risk_tier"] == "HIGH")
    print("[+] Scored: " + str(c) + " Critical | " + str(h) + " High\n")

    report = ReportGenerator().generate(results)
    print(report)

    if output:
        output_dir = os.path.dirname(output)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        with open(output, "w") as f:
            json.dump(results, f, indent=4)
        print("[+] Exported: " + output)


def _configure_console():
    """Keep Unicode reports readable on Windows and redirected terminals."""
    import sys
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


if __name__ == "__main__":
    _configure_console()
    ap = argparse.ArgumentParser(description="Dark Web and Threat Feed Monitor")
    ap.add_argument("--feed", default="data/threat_feed.json")
    ap.add_argument("--output", default="reports/threat_report.json")
    args = ap.parse_args()
    run(args.feed, args.output)
