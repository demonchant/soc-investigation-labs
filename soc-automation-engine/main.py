"""
SOC Automation Engine - Entry Point
Author: github.com/demonchant
"""
import json
import argparse
import logging
from parser.log_parser import LogParser
from detection.engine import DetectionEngine
from reports.report_generator import ReportGenerator
from detection.rule_loader import load_rules

logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


def run_pipeline(log_file, output_file="reports/incident_report.json"):
    print("\n[*] SOC Automation Engine v1.0 — Starting pipeline...\n")

    logger.info(f"Ingesting logs from: {log_file}")
    parser = LogParser()
    logs = parser.parse(log_file)
    print(f"[+] Parsed {len(logs)} log entries.")

    rules = load_rules("rules/rules.yaml")
    print(f"[+] Loaded {len(rules)} detection rules.")

    engine = DetectionEngine(rules)
    alerts = engine.process(logs)
    print(f"[+] Detection complete. {len(alerts)} alert(s) triggered.\n")

    reporter = ReportGenerator()
    report = reporter.generate(alerts)
    print(report)

    import os
    os.makedirs("reports", exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(alerts, f, indent=4)
    print(f"[+] Incident report saved to: {output_file}")
    print("[*] Pipeline complete.\n")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="SOC Automation Engine")
    ap.add_argument("--logs", default="data/sample_logs.json")
    ap.add_argument("--output", default="reports/incident_report.json")
    args = ap.parse_args()
    run_pipeline(args.logs, args.output)
