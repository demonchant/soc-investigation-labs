import argparse
import json
import os
import sys

from reports.report_generator import generate_report
from scanner.identity_detector import IdentityThreatDetector


def run(input_path, output_path):
    with open(input_path, encoding="utf-8") as handle:
        events = json.load(handle)
    findings = IdentityThreatDetector().analyze(events)
    print(generate_report(findings))
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(findings, handle, indent=2)
    return findings


def configure_console():
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


if __name__ == "__main__":
    configure_console()
    parser = argparse.ArgumentParser(description="Analyze identity provider security events")
    parser.add_argument("--input", default="data/identity_events.json")
    parser.add_argument("--output", default="reports/identity_findings.json")
    arguments = parser.parse_args()
    run(arguments.input, arguments.output)
