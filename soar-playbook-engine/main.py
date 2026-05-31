"""
SOAR Playbook Engine — Entry Point
Loads incidents, matches each to a playbook by trigger type,
executes automated response steps with full audit trail.
Author: github.com/demonchant
"""
import json, argparse, logging, os
from engine.playbook_runner import PlaybookRunner
from reports.report_generator import ReportGenerator

logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

def run(incidents_file="data/incidents.json",
        playbooks_file="playbooks/playbooks.json", output=None):
    print("[*] SOAR Playbook Engine v1.0")
    with open(incidents_file) as f: incidents = json.load(f)
    with open(playbooks_file) as f: playbooks = json.load(f)
    print(f"[+] {len(incidents)} incident(s) | {len(playbooks)} playbook(s)\n")

    runner = PlaybookRunner()
    executions = []

    for inc in incidents:
        pb = runner.find_playbook(playbooks, inc["type"])
        if not pb:
            print(f"  [SKIP] {inc['id']} — no playbook for '{inc['type']}'")
            continue
        print(f"  [RUN ] {inc['id']} — {pb['name']}")
        result = runner.run(pb, inc)
        executions.append(result)
        print(f"         {result['final_status']} | "
              f"{result['steps_passed']}/{result['steps_total']} steps passed"
              + (" | ESCALATED" if result["escalated"] else ""))

    print()
    report = ReportGenerator().generate(executions)
    print(report)

    if output:
        os.makedirs(os.path.dirname(output), exist_ok=True)
        with open(output,"w") as f: json.dump(executions, f, indent=4)
        print(f"[+] Exported: {output}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--incidents", default="data/incidents.json")
    ap.add_argument("--playbooks", default="playbooks/playbooks.json")
    ap.add_argument("--output", default="reports/soar_execution.json")
    args = ap.parse_args()
    run(args.incidents, args.playbooks, args.output)
