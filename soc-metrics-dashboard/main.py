"""
SOC Metrics & KPI Dashboard
Computes MTTA, MTTR, MTTC, MTTI, true/false positive rates,
SLA compliance, and analyst workload distribution from SOC alert
and incident data. Produces a monthly KPI report.
Author: github.com/demonchant
"""
import json, argparse, logging, os
from calculator.metrics_calculator import MetricsCalculator
from reports.report_generator import ReportGenerator

logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

def run(data_file="data/soc_metrics.json", output=None):
    print("[*] SOC Metrics Dashboard v1.0")
    with open(data_file) as f: data = json.load(f)
    print(f"[+] {len(data['alerts'])} alerts | {len(data['incidents'])} incidents loaded.")
    metrics = MetricsCalculator().calculate(data)
    report  = ReportGenerator().generate(metrics)
    print("\n" + report)
    if output:
        os.makedirs(os.path.dirname(output), exist_ok=True)
        with open(output,"w") as f: json.dump(metrics, f, indent=4)
        print(f"[+] Exported: {output}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--data",   default="data/soc_metrics.json")
    ap.add_argument("--output", default="reports/soc_kpis.json")
    args = ap.parse_args()
    run(args.data, args.output)
