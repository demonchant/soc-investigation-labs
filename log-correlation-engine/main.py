"""
Multi-Source Log Correlation Engine
Ingests Windows, Firewall, Proxy, and DNS logs, classifies events by type,
then applies correlation rules to detect multi-stage attack chains
that no single-source rule would catch.
Author: github.com/demonchant
"""
import json, argparse, logging, os
from collections import Counter
from correlator.event_classifier import classify
from correlator.correlation_engine import CorrelationEngine
from reports.report_generator import ReportGenerator

logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

def run(logs_file="data/multi_source_logs.json",
        rules_file="rules/correlation_rules.json", output=None):
    print("[*] Multi-Source Log Correlation Engine v1.0")
    with open(logs_file) as f: raw_logs = json.load(f)
    with open(rules_file) as f: rules = json.load(f)
    print(f"[+] {len(raw_logs)} log events loaded across sources.")
    print(f"[+] {len(rules)} correlation rules loaded.\n")

    logs = [classify(log) for log in raw_logs]
    source_counts = dict(Counter(l.get("source","unknown") for l in logs))

    engine = CorrelationEngine(rules)
    alerts = engine.run(logs)
    print(f"[+] {len(alerts)} correlated alert(s) detected.\n")

    report = ReportGenerator().generate(alerts, len(logs), source_counts)
    print(report)

    if output:
        os.makedirs(os.path.dirname(output), exist_ok=True)
        with open(output,"w") as f: json.dump({"alerts":alerts}, f, indent=4)
        print(f"[+] Exported: {output}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--logs", default="data/multi_source_logs.json")
    ap.add_argument("--rules", default="rules/correlation_rules.json")
    ap.add_argument("--output", default="reports/correlation_report.json")
    args = ap.parse_args()
    run(args.logs, args.rules, args.output)
