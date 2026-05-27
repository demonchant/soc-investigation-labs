"""
Honeypot Log Analyser & Attacker Profiler
Ingests honeypot interaction logs (SSH/HTTP/FTP/RDP), classifies MITRE ATT&CK
TTPs per attacker session, extracts IOCs, generates threat actor profiles.
Author: github.com/demonchant
"""
import json, argparse, logging, os
from profiler.session_aggregator import SessionAggregator
from profiler.ttp_classifier import TTPClassifier
from intelligence.ioc_extractor import IOCExtractor
from reports.report_generator import ReportGenerator

logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

def run(log_file="data/honeypot_logs.json", output=None):
    print("[*] Honeypot Attacker Profiler v1.0")
    with open(log_file) as f:
        events = json.load(f)
    print("[+] " + str(len(events)) + " honeypot events loaded.")
    sessions = SessionAggregator().aggregate(events)
    print("[+] " + str(len(sessions)) + " attacker session(s) identified.")
    profiles = TTPClassifier().classify(sessions)
    iocs = IOCExtractor().extract(sessions)
    print("[+] IOC extraction complete.\n")
    report = ReportGenerator().generate(profiles, iocs)
    print(report)
    if output:
        os.makedirs(os.path.dirname(output), exist_ok=True)
        with open(output, "w") as f:
            json.dump({"profiles": profiles, "iocs": iocs}, f, indent=4)
        print("[+] Exported: " + output)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--logs", default="data/honeypot_logs.json")
    ap.add_argument("--output", default="reports/attacker_profiles.json")
    args = ap.parse_args()
    run(args.logs, args.output)
