"""
Cloud Misconfiguration Scanner
Audits AWS infrastructure config for security misconfigurations:
public S3 buckets, exposed database/management ports, IAM users
without MFA, stale access keys, overprivileged accounts, CloudTrail
gaps, and weak password policies. MITRE ATT&CK + CIS Benchmark mapped.
Author: github.com/demonchant
"""
import json, argparse, logging, os
from scanners.cloud_scanner import CloudScanner
from reports.report_generator import ReportGenerator

logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

def run(config_file="data/cloud_config.json", output=None):
    print("[*] Cloud Misconfiguration Scanner v1.0")
    with open(config_file) as f: config = json.load(f)
    findings = CloudScanner().scan(config)
    c = sum(1 for f in findings if f["severity"]=="critical")
    print(f"[+] {len(findings)} finding(s) — {c} Critical.\n")
    report = ReportGenerator().generate(findings)
    print(report)
    if output:
        os.makedirs(os.path.dirname(output), exist_ok=True)
        with open(output,"w") as f: json.dump(findings, f, indent=4)
        print(f"[+] Exported: {output}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="data/cloud_config.json")
    ap.add_argument("--output", default="reports/cloud_scan.json")
    args = ap.parse_args()
    run(args.config, args.output)
