import argparse
import json
import os
import sys

from reports.report_generator import generate_report
from scanner.health_monitor import TelemetryHealthMonitor


def run(input_path, output_path):
    with open(input_path, encoding="utf-8") as handle:
        sources = json.load(handle)
    findings = TelemetryHealthMonitor().analyze(sources)
    print(generate_report(findings, len(sources)))
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
    parser = argparse.ArgumentParser(description="Assess security telemetry pipeline health")
    parser.add_argument("--input", default="data/source_health.json")
    parser.add_argument("--output", default="reports/telemetry_findings.json")
    arguments = parser.parse_args()
    run(arguments.input, arguments.output)
