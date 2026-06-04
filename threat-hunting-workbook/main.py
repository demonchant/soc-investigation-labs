"""
Threat Hunting Workbook
Executes structured, hypothesis-driven threat hunts against process,
network, and authentication logs. Hunts for: phishing execution chains,
LOLBin abuse, NTLM lateral movement, process masquerading, and
non-browser C2 callbacks. All findings mapped to MITRE ATT&CK.
Author: github.com/demonchant
"""
import json, argparse, logging, os
from engine.hunt_engine import HuntEngine
from reports.report_generator import ReportGenerator

logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

def run(data_file="data/hunt_data.json",
        hunts_file="hunts/hunt_hypotheses.json", output=None):
    print("[*] Threat Hunting Workbook v1.0")
    with open(data_file)  as f: hunt_data = json.load(f)
    with open(hunts_file) as f: hunts = json.load(f)
    total_events = sum(len(v) for v in hunt_data.values())
    print(f"[+] {total_events} log events | {len(hunts)} hunt hypotheses loaded.\n")

    results = HuntEngine(hunt_data).run(hunts)
    hits = sum(1 for r in results if r["status"] == "HIT")
    print(f"[+] {hits}/{len(hunts)} hunts confirmed.\n")

    report = ReportGenerator().generate(results)
    print(report)

    if output:
        os.makedirs(os.path.dirname(output), exist_ok=True)
        with open(output, "w") as f: json.dump(results, f, indent=4)
        print(f"[+] Exported: {output}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--data",   default="data/hunt_data.json")
    ap.add_argument("--hunts",  default="hunts/hunt_hypotheses.json")
    ap.add_argument("--output", default="reports/hunt_results.json")
    args = ap.parse_args()
    run(args.data, args.hunts, args.output)
