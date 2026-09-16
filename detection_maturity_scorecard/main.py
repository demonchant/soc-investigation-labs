import json, argparse, logging, os
from scanner.maturity_scorecard import MaturityScorecard
from reports.report_generator import ReportGenerator
logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

def run(data_file="data/program_data.json", output=None):
    print("[*] Detection Maturity Scorecard v1.0")
    with open(data_file) as f: data = json.load(f)
    findings = MaturityScorecard().assess_all(data)
    c = sum(1 for f in findings if f["severity"]=="critical")
    print("[+] {} finding(s) — {} Critical.".format(len(findings), c))
    print()
    print(ReportGenerator().generate(findings, data))
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
    ap.add_argument("--data",   default="data/program_data.json")
    ap.add_argument("--output", default="reports/maturity_report.json")
    args = ap.parse_args()
    run(args.data, args.output)
