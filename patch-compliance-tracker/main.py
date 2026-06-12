import json, argparse, logging, os
from tracker.compliance_tracker import ComplianceTracker
from reports.report_generator import ReportGenerator
logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

def run(assets_file="data/assets.json", sla_file="data/sla_targets.json", output=None):
    print("[*] Patch Compliance Tracker v1.0")
    with open(assets_file) as f: assets = json.load(f)
    with open(sla_file) as f: sla = json.load(f)
    findings = ComplianceTracker(sla).evaluate(assets)
    c = sum(1 for f in findings if f["severity"]=="critical")
    print("[+] {} finding(s) — {} Critical.".format(len(findings),c))
    print()
    print(ReportGenerator().generate(findings, assets))
    if output:
        os.makedirs(os.path.dirname(output), exist_ok=True)
        with open(output,"w") as f: json.dump(findings, f, indent=4)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--assets", default="data/assets.json")
    ap.add_argument("--sla", default="data/sla_targets.json")
    ap.add_argument("--output", default="reports/patch_compliance.json")
    args = ap.parse_args()
    run(args.assets, args.sla, args.output)
