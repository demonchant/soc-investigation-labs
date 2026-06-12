import json, argparse, logging, os
from analyser.policy_analyser import PolicyAnalyser
from reports.report_generator import ReportGenerator
logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

def run(accounts_file="data/accounts.json", policy_file="data/policy.json", output=None):
    print("[*] Password Policy Analyser v1.0")
    with open(accounts_file) as f: accounts = json.load(f)
    with open(policy_file) as f: policy = json.load(f)
    findings = PolicyAnalyser(policy).analyse(accounts)
    c = sum(1 for f in findings if f["severity"]=="critical")
    print("[+] {} finding(s) — {} Critical.".format(len(findings), c))
    print()
    print(ReportGenerator().generate(findings, accounts, policy))
    if output:
        os.makedirs(os.path.dirname(output), exist_ok=True)
        with open(output,"w") as f: json.dump(findings, f, indent=4)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--accounts", default="data/accounts.json")
    ap.add_argument("--policy", default="data/policy.json")
    ap.add_argument("--output", default="reports/password_audit.json")
    args = ap.parse_args()
    run(args.accounts, args.policy, args.output)
