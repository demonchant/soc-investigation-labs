"""
Digital Forensics Artifact Collector & Analyser
Processes forensic artifacts from a compromised Windows host:
running processes, network connections, registry run keys, recently
modified files, scheduled tasks, prefetch execution traces, and event
log summaries. Identifies IOCs, persistence mechanisms, C2 connections,
and attack tool traces for incident response investigations.
Author: github.com/demonchant
"""
import json, argparse, logging, os
from analyser.artifact_analyser import ArtifactAnalyser
from reports.report_generator import ReportGenerator

logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

def run(artifacts_file="data/forensic_artifacts.json", output=None):
    print("[*] Digital Forensics Artifact Collector v1.0")
    with open(artifacts_file) as f:
        artifacts = json.load(f)

    host = artifacts.get("host","unknown")
    print(f"[+] Artifacts loaded from host: {host}")
    print(f"[+] Collection time: {artifacts.get('collection_time','')}\n")

    findings = ArtifactAnalyser().analyse(artifacts)
    c = sum(1 for f in findings if f["severity"]=="critical")
    print(f"[+] {len(findings)} finding(s) — {c} Critical.\n")

    metadata = {
        "host":            artifacts.get("host"),
        "collection_time": artifacts.get("collection_time"),
        "collector":       artifacts.get("collector"),
    }
    report = ReportGenerator().generate(findings, metadata)
    print(report)

    if output:
        os.makedirs(os.path.dirname(output), exist_ok=True)
        with open(output,"w") as f:
            json.dump({"metadata": metadata, "findings": findings}, f, indent=4)
        print(f"[+] Exported: {output}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifacts", default="data/forensic_artifacts.json")
    ap.add_argument("--output",    default="reports/forensics_report.json")
    args = ap.parse_args()
    run(args.artifacts, args.output)
