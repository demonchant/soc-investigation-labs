import json, argparse, logging, os
from scanner.detection_pipeline import DetectionPipeline
from reports.report_generator import ReportGenerator
logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

def run(data_file="data/rules_and_corpus.json", output=None):
    print("[*] Detection-as-Code Pipeline v1.0")
    with open(data_file) as f: data = json.load(f)
    findings = DetectionPipeline().run_pipeline(data)
    blocked = sum(1 for f in findings if f["stage"]=="GATE" and "BLOCKED" in f["title"])
    print("[+] {} pipeline event(s) — {} rule(s) BLOCKED from deployment.".format(len(findings), blocked))
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
    ap.add_argument("--data",   default="data/rules_and_corpus.json")
    ap.add_argument("--output", default="reports/pipeline_report.json")
    args = ap.parse_args()
    run(args.data, args.output)
