import json, argparse, logging, os
from scanner.container_scanner import ContainerScanner
from reports.report_generator import ReportGenerator
logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

def run(containers_file="data/containers.json", output=None):
    print("[*] Container Security Scanner v1.0")
    with open(containers_file) as f: containers = json.load(f)
    findings = ContainerScanner().scan_all(containers)
    c = sum(1 for f in findings if f["severity"]=="critical")
    print("[+] {} finding(s) — {} Critical.".format(len(findings),c))
    print()
    print(ReportGenerator().generate(findings, containers))
    if output:
        os.makedirs(os.path.dirname(output), exist_ok=True)
        with open(output,"w") as f: json.dump(findings, f, indent=4)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--containers", default="data/containers.json")
    ap.add_argument("--output", default="reports/container_scan.json")
    args = ap.parse_args()
    run(args.containers, args.output)
