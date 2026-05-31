"""
Splunk SPL Detection Rule Library
Loads, validates, and catalogues 10 production-ready Splunk SPL detection
rules mapped to MITRE ATT&CK. Simulates a detection-as-code CI/CD pipeline.
Author: github.com/demonchant
"""
import json, argparse, logging, os
from validator.spl_validator import SPLValidator
from reports.report_generator import ReportGenerator

logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

def run(rules_file="data/spl_rules.json", output=None):
    print("[*] Splunk SPL Detection Rule Library v1.0")
    with open(rules_file) as f:
        rules = json.load(f)
    print(f"[+] Loaded {len(rules)} detection rules.")

    validator = SPLValidator()
    validation = validator.validate_all(rules)
    print(f"[+] Validation: {validation['passed']}/{validation['total']} rules passed.\n")

    for res in validation["results"]:
        status = res["status"]
        tag = "[PASS]" if status == "PASS" else "[FAIL]"
        print(f"  {tag} {res['id']} — {res['name']}")
        for err in res["errors"]:
            print(f"         ERROR: {err}")
        for warn in res["warnings"]:
            print(f"         WARN : {warn}")

    print()
    report = ReportGenerator().generate(rules, validation)
    print(report)

    if output:
        os.makedirs(os.path.dirname(output), exist_ok=True)
        with open(output, "w") as f:
            json.dump({"rules": rules, "validation": validation}, f, indent=4)
        print(f"[+] Exported: {output}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", default="data/spl_rules.json")
    ap.add_argument("--output", default="reports/spl_library_report.json")
    args = ap.parse_args()
    run(args.rules, args.output)
