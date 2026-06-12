import json, argparse, logging, os
from checks.api_checker import APIChecker
from reports.report_generator import ReportGenerator
logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

def run(endpoints_file="data/api_endpoints.json", requests_file="data/api_requests.json", output=None):
    print("[*] API Security Tester v1.0 — OWASP API Top 10")
    with open(endpoints_file) as f: endpoints = json.load(f)
    with open(requests_file) as f: requests = json.load(f)
    checker = APIChecker()
    checker.check_endpoints(endpoints)
    checker.check_requests(requests, endpoints)
    findings = checker.findings
    c = sum(1 for f in findings if f["severity"]=="critical")
    print("[+] {} finding(s) — {} Critical.".format(len(findings),c))
    print()
    print(ReportGenerator().generate(findings))
    if output:
        os.makedirs(os.path.dirname(output), exist_ok=True)
        with open(output,"w") as f: json.dump(findings, f, indent=4)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--endpoints", default="data/api_endpoints.json")
    ap.add_argument("--requests",  default="data/api_requests.json")
    ap.add_argument("--output",    default="reports/api_security.json")
    args = ap.parse_args()
    run(args.endpoints, args.requests, args.output)
