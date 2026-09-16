import json, argparse, logging, os
from auditor.zt_auditor import ZeroTrustAuditor
from reports.report_generator import ReportGenerator
logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

def run(config_file="data/zt_config.json", output=None):
    print("[*] Zero Trust Policy Auditor v1.0")
    with open(config_file) as f: config = json.load(f)
    findings = ZeroTrustAuditor().audit(config)
    c = sum(1 for f in findings if f["severity"]=="critical")
    print("[+] {} finding(s) — {} Critical.".format(len(findings),c))
    print()
    print(ReportGenerator().generate(findings))
    if output:
        output_dir = os.path.dirname(output)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        with open(output,"w") as f: json.dump(findings, f, indent=4)

def _configure_console():
    """Keep Unicode reports readable on Windows and redirected terminals."""
    import sys
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


if __name__ == "__main__":
    _configure_console()
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="data/zt_config.json")
    ap.add_argument("--output", default="reports/zt_audit.json")
    args = ap.parse_args()
    run(args.config, args.output)
