"""
Phishing Email Analyser
Analyses email headers (SPF/DKIM/DMARC, typosquatting, display-name spoofing)
and body content (urgency, BEC patterns, credential harvesting, malicious URLs,
macro attachments) to produce a phishing verdict and response recommendation.
Author: github.com/demonchant
"""
import json, argparse, logging, os
from parser.email_parser import EmailParser
from analyser.header_analyser import HeaderAnalyser
from analyser.content_analyser import ContentAnalyser
from scoring.risk_scorer import RiskScorer
from reports.report_generator import ReportGenerator

logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

def run(emails_file="data/emails.json", output=None):
    print("[*] Phishing Email Analyser v1.0")
    emails = EmailParser().load(emails_file)
    print(f"[+] {len(emails)} email(s) loaded.\n")

    ha = HeaderAnalyser()
    ca = ContentAnalyser()
    scorer = RiskScorer()
    results = []

    for email in emails:
        hf, hs = ha.analyse(email)
        cf, cs = ca.analyse(email)
        result = scorer.score(email, hf, hs, cf, cs)
        results.append(result)
        print(f"  [{result['verdict']:<12}] {email['id']} — Score {result['final_score']}/100 — {email['subject'][:50]}")

    print()
    report = ReportGenerator().generate(results)
    print(report)

    if output:
        os.makedirs(os.path.dirname(output), exist_ok=True)
        with open(output,"w") as f:
            json.dump(results, f, indent=4)
        print(f"[+] Exported: {output}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--emails", default="data/emails.json")
    ap.add_argument("--output", default="reports/phishing_report.json")
    args = ap.parse_args()
    run(args.emails, args.output)
