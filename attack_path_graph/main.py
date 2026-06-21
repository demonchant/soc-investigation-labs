import json, argparse, logging, os
from scanner.attack_path_engine import AttackPathEngine
from reports.report_generator import ReportGenerator
logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

def run(data_file="data/ad_graph.json", output=None):
    print("[*] Attack Path Graph Engine v1.0")
    with open(data_file) as f: data = json.load(f)
    findings = AttackPathEngine().analyze_all(data)
    c = sum(1 for f in findings if f["severity"]=="critical")
    print("[+] {} finding(s) — {} Critical.".format(len(findings), c))
    print()
    print(ReportGenerator().generate(findings, data))
    if output:
        os.makedirs(os.path.dirname(output), exist_ok=True)
        with open(output,"w") as f: json.dump(findings, f, indent=4)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--data",   default="data/ad_graph.json")
    ap.add_argument("--output", default="reports/attack_path_report.json")
    args = ap.parse_args()
    run(args.data, args.output)
