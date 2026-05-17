"""
Threat Intel Enrichment Tool — CLI Entry Point
Supports IP, Domain, and File Hash lookups with risk scoring.
Author: github.com/demonchant
"""
import sys
import json
import argparse
from core.enricher import ThreatIntelEnricher


def banner():
    print("""
  ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗
  ╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝
     ██║   ███████║██████╔╝█████╗  ███████║   ██║   
     ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║   
     ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║   
     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   
         INTEL ENRICHMENT TOOL v2.0
         SOC Threat Intelligence Pipeline
    """)


def run_interactive(enricher):
    banner()
    print("  Enter IPs, Domains, or File Hashes to analyze.")
    print("  Type 'exit' to quit | 'batch' for multi-input mode\n")

    while True:
        try:
            query = input("  > Indicator: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n[*] Session ended.")
            break

        if not query:
            continue
        if query.lower() == "exit":
            print("[*] Goodbye.")
            break
        if query.lower() == "batch":
            run_batch_mode(enricher)
            continue

        result = enricher.analyze(query)
        print_result(result)


def run_batch_mode(enricher):
    print("\n  Batch mode — Enter indicators (one per line). Empty line to finish:")
    indicators = []
    while True:
        line = input("  > ").strip()
        if not line:
            break
        indicators.append(line)

    results = []
    for ind in indicators:
        result = enricher.analyze(ind)
        print_result(result)
        results.append(result)

    export = input("\n  Export results to JSON? (y/n): ").strip().lower()
    if export == "y":
        with open("reports/batch_results.json", "w") as f:
            json.dump(results, f, indent=4)
        print("  [+] Saved to reports/batch_results.json\n")


def print_result(result):
    if "error" in result:
        print(f"\n  [ERROR] {result['error']}\n")
        return

    risk = result.get("risk_score", 0)
    if risk >= 70:
        level = "CRITICAL"
    elif risk >= 50:
        level = "HIGH"
    elif risk >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    print(f"""
  ┌─────────────────────────────────────────┐
  │  ENRICHMENT RESULT
  ├─────────────────────────────────────────┤
  │  Indicator   : {result.get('indicator', 'N/A')}
  │  Type        : {result.get('type', 'N/A').upper()}
  │  Reputation  : {result.get('reputation', 'N/A').upper()}
  │  Country     : {result.get('country', 'N/A')}
  │  Detected By : {', '.join(result.get('detected_by', []))}
  │  Risk Score  : {risk}/100 [{level}]
  │  Cached      : {result.get('cached', False)}
  └─────────────────────────────────────────┘
""")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Threat Intel Enrichment Tool")
    ap.add_argument("--indicator", help="Single indicator to analyze")
    ap.add_argument("--output", help="Save result to JSON file")
    args = ap.parse_args()

    import os
    os.makedirs("reports", exist_ok=True)

    enricher = ThreatIntelEnricher()

    if args.indicator:
        result = enricher.analyze(args.indicator)
        print_result(result)
        if args.output:
            with open(args.output, "w") as f:
                json.dump(result, f, indent=4)
            print(f"[+] Result saved to {args.output}")
    else:
        run_interactive(enricher)
