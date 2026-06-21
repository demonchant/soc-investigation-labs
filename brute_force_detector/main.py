import json, argparse, logging, os
from scanner.brute_force_detector import BruteForceDetector
from reports.report_generator import ReportGenerator
logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

def run(data_file="data/auth_events.json", output=None):
    print("[*] Brute Force & Account Lockout Detector v1.0")
    with open(data_file) as f: data = json.load(f)
    findings = BruteForceDetector().detect_all(data)
    c = sum(1 for f in findings if f["severity"]=="critical")
    print("[+] {} finding(s) — {} Critical.".format(len(findings), c))
    print()
    print(ReportGenerator().generate(findings, data))
    if output:
        os.makedirs(os.path.dirname(output), exist_ok=True)
        with open(output,"w") as f: json.dump(findings, f, indent=4)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--data",   default="data/auth_events.json")
    ap.add_argument("--output", default="reports/brute_force_report.json")
    args = ap.parse_args()
    run(args.data, args.output)
