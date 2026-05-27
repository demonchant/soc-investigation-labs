"""
Network Anomaly Detection Engine
Builds per-host statistical baselines then detects Z-score deviations,
C2 beaconing, DNS tunneling, port scanning, SMB lateral movement.
Author: github.com/demonchant
"""
import json, argparse, logging, os
from analyzer.flow_analyzer import FlowAnalyzer
from baseline.profiler import BaselineProfiler
from detection.anomaly_engine import AnomalyEngine
from reports.report_generator import ReportGenerator

logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

def run(flow_file="data/network_flows.json", output=None):
    print("[*] Network Anomaly Detection Engine v1.0")
    with open(flow_file) as f:
        raw = json.load(f)
    print(f"[+] Loaded {len(raw)} network flows.")
    flows = FlowAnalyzer().enrich(raw)
    profiles = BaselineProfiler().build(flows)
    print(f"[+] Baseline built for {len(profiles)} host(s).")
    alerts = AnomalyEngine(profiles).run(flows)
    print(f"[+] {len(alerts)} alert(s) detected.\n")
    report = ReportGenerator().generate(alerts, profiles)
    print(report)
    if output:
        os.makedirs(os.path.dirname(output), exist_ok=True)
        with open(output, "w") as f:
            json.dump({"alerts": alerts, "profiles": profiles}, f, indent=4)
        print(f"[+] Exported: {output}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--flows", default="data/network_flows.json")
    ap.add_argument("--output", default="reports/anomaly_report.json")
    args = ap.parse_args()
    run(args.flows, args.output)
