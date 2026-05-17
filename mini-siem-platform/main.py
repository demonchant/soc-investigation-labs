"""
Mini SIEM Platform - Pipeline Orchestrator
Author: github.com/demonchant
"""
import logging, argparse, os
from database.models import init_db
from ingestion.log_ingestor import LogIngestor
from detection.rule_engine import RuleEngine

logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


def run(log_file="data/sample_logs.json", rules_path="detection/rules.yaml"):
    print("\n[*] Mini SIEM Platform v2.0 — Starting pipeline...\n")

    print("[+] Initializing database...")
    init_db()

    print(f"[+] Ingesting logs from: {log_file}")
    ingestor = LogIngestor()
    count = ingestor.ingest(log_file)
    print(f"[+] {count} log entries ingested.")

    print("[+] Running detection engine...")
    engine = RuleEngine(rules_path=rules_path)
    engine.run()

    print("[*] Pipeline complete. Start the API with: python api/server.py\n")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Mini SIEM Platform")
    ap.add_argument("--logs", default="data/sample_logs.json")
    ap.add_argument("--rules", default="detection/rules.yaml")
    args = ap.parse_args()
    run(args.logs, args.rules)
