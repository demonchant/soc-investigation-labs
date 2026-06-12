import json, argparse, logging, os
from analyser.dns_analyser import DNSAnalyser
from reports.report_generator import ReportGenerator
logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

def run(events_file="data/dns_events.json", threats_file="data/threat_ips.json", output=None):
    print("[*] DNS Security Monitor v1.0")
    with open(events_file) as f: events = json.load(f)
    with open(threats_file) as f: threat_ips = json.load(f)
    alerts = DNSAnalyser(threat_ips).run(events)
    c = sum(1 for a in alerts if a["severity"]=="critical")
    print("[+] {} alert(s) — {} Critical.".format(len(alerts), c))
    print()
    print(ReportGenerator().generate(alerts, len(events)))
    if output:
        os.makedirs(os.path.dirname(output), exist_ok=True)
        with open(output,"w") as f: json.dump(alerts, f, indent=4)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", default="data/dns_events.json")
    ap.add_argument("--threats", default="data/threat_ips.json")
    ap.add_argument("--output", default="reports/dns_alerts.json")
    args = ap.parse_args()
    run(args.events, args.threats, args.output)
