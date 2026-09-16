"""Library Report Generator — Produces a summary of all SPL detection rules."""
from datetime import datetime

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}

class ReportGenerator:
    def generate(self, rules, validation):
        r = []
        r.append("=" * 68)
        r.append("  SPLUNK SPL DETECTION RULE LIBRARY — CATALOGUE")
        r.append(f"  Generated  : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        r.append(f"  Total Rules: {len(rules)}   |   Validation: {validation['passed']}/{validation['total']} passed ({validation['pass_rate']}%)")
        r.append("=" * 68)

        # Coverage summary
        by_sev = {}
        for r2 in rules:
            s = r2.get("severity","unknown")
            by_sev[s] = by_sev.get(s, 0) + 1
        r.append("\n  SEVERITY BREAKDOWN")
        for sev in ["critical","high","medium","low"]:
            if sev in by_sev:
                r.append(f"    {sev.upper():<14}: {by_sev[sev]} rule(s)")

        r.append("\n  MITRE ATT&CK COVERAGE")
        for rule in rules:
            r.append(f"    {rule['id']}  {rule['mitre']:<20}  {rule['name']}")

        r.append("\n" + "=" * 68)
        r.append("  RULE DETAILS\n")

        sorted_rules = sorted(rules, key=lambda x: SEV_ORDER.get(x.get("severity",""), 9))
        for rule in sorted_rules:
            r.append(f"  [{rule['id']}] [{rule['severity'].upper()}] {rule['name']}")
            r.append(f"    MITRE     : {rule['mitre']}")
            r.append(f"    Log Source: {rule.get('log_source','N/A')}")
            r.append(f"    Event IDs : {', '.join(rule.get('event_ids',[]))}")
            r.append(f"    Purpose   : {rule['description']}")
            r.append(f"    Tuning    : {rule.get('tuning_notes','N/A')}")
            r.append(f"    Response  : {rule['response']}")
            r.append("")
            r.append("    SPL Query:")
            for line in rule["spl"].strip().split("\n"):
                r.append("      " + line)
            r.append("")
            r.append("  " + "-" * 64)
            r.append("")

        return "\n".join(r)
