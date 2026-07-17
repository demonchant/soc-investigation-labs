import json, argparse, logging, os
from scanner.hypothesis_builder import HypothesisBuilder
from reports.report_generator import ReportGenerator
logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

def run(data_file="data/hypotheses.json", output=None):
    print("[*] Threat Hunt Hypothesis Builder v1.0")
    with open(data_file) as f: data = json.load(f)
    findings = HypothesisBuilder().analyze_all(data)
    c = sum(1 for f in findings if f["severity"] == "critical")
    print("[+] {} finding(s) — {} Critical.".format(len(findings), c))
    print()
    print(ReportGenerator().generate(findings, data))
    if output:
        os.makedirs(os.path.dirname(output), exist_ok=True)
        with open(output, "w") as f: json.dump(findings, f, indent=4)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--data",   default="data/hypotheses.json")
    ap.add_argument("--output", default="reports/hypothesis_report.json")
    args = ap.parse_args()
    run(args.data, args.output)
