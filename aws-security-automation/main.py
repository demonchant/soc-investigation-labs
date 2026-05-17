"""
AWS Security Automation System — Entry Point
Author: github.com/demonchant
"""
import argparse, json, os, logging
from collector.log_collector import LogCollector
from processor.normalizer import normalize
from detection.engine import IAMDetectionEngine
from reports.report_generator import ReportGenerator

logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


def run(log_file="data/cloudtrail_logs.json", output_file=None):
    print("\n[*] AWS Security Automation System v2.0\n")

    print(f"[+] Collecting logs from: {log_file}")
    collector = LogCollector()
    raw_logs = collector.collect(log_file)
    print(f"[+] {len(raw_logs)} raw event(s) collected.")

    normalized_logs = []
    for log in raw_logs:
        n = normalize(log)
        if n:
            normalized_logs.append(n)
    print(f"[+] {len(normalized_logs)} event(s) normalised.\n")

    engine = IAMDetectionEngine()
    alert_count = engine.run(normalized_logs)
    print(f"[+] {alert_count} alert(s) generated.\n")

    report = ReportGenerator().generate()
    print(report)

    if output_file:
        from alerts.alert_manager import get_alerts
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, "w") as f:
            json.dump(get_alerts(), f, indent=4)
        print(f"[+] Alerts exported to: {output_file}")

    print("[*] Pipeline complete.\n")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="AWS Security Automation System")
    ap.add_argument("--logs", default="data/cloudtrail_logs.json")
    ap.add_argument("--output", default="reports/aws_security_alerts.json")
    args = ap.parse_args()
    run(args.logs, args.output)
