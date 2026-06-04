"""
Firewall Rule Auditor
Parses firewall rulesets and detects dangerous misconfigurations:
overly permissive rules, internet-exposed management ports, insecure
cleartext protocols, stale/unreviewed rules, shadow rules, and missing
egress controls. MITRE ATT&CK mapped.
Author: github.com/demonchant
"""
import json, argparse, logging, os
from auditor.rule_auditor import RuleAuditor
from reports.report_generator import ReportGenerator

logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

def run(rules_file="data/firewall_rules.json", output=None):
    print("[*] Firewall Rule Auditor v1.0")
    with open(rules_file) as f: rules = json.load(f)
    enabled = sum(1 for r in rules if r.get("enabled"))
    print(f"[+] {len(rules)} rules loaded ({enabled} enabled).")
    findings = RuleAuditor().audit(rules)
    c = sum(1 for f in findings if f["severity"]=="critical")
    print(f"[+] {len(findings)} finding(s) — {c} Critical.\n")
    report = ReportGenerator().generate(findings, len(rules))
    print(report)
    if output:
        os.makedirs(os.path.dirname(output), exist_ok=True)
        with open(output,"w") as f: json.dump(findings, f, indent=4)
        print(f"[+] Exported: {output}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", default="data/firewall_rules.json")
    ap.add_argument("--output", default="reports/firewall_audit.json")
    args = ap.parse_args()
    run(args.rules, args.output)
