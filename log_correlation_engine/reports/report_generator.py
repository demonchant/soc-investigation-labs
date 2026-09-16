"""Log Correlation Report Generator."""
from datetime import datetime

SEV_ORDER = {"critical":0,"high":1,"medium":2,"low":3}
SEV_LABEL = {"critical":"[CRITICAL]","high":"[HIGH]","medium":"[MEDIUM]","low":"[LOW]"}

class ReportGenerator:
    def generate(self, alerts, log_count, source_counts):
        alerts = sorted(alerts, key=lambda a: SEV_ORDER.get(a["severity"],9))
        r = []
        r.append("="*65)
        r.append("  MULTI-SOURCE LOG CORRELATION ENGINE — REPORT")
        r.append(f"  Generated : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        r.append(f"  Logs      : {log_count} events across {len(source_counts)} source(s)")
        for src, cnt in source_counts.items():
            r.append(f"    {src:<12}: {cnt} events")
        c = sum(1 for a in alerts if a["severity"]=="critical")
        h = sum(1 for a in alerts if a["severity"]=="high")
        r.append(f"  Alerts    : {len(alerts)} correlated  |  {c} Critical  |  {h} High")
        r.append("="*65)
        for i, a in enumerate(alerts, 1):
            lbl = SEV_LABEL.get(a["severity"],"[?]")
            r.append(f"\n  [{i}] {lbl} [{a['rule_id']}] {a['rule_name']}")
            r.append(f"       Source IP   : {a['src_ip']}")
            r.append(f"       MITRE       : {a['mitre_technique']}")
            r.append(f"       Description : {a['description']}")
            r.append(f"       Span        : {a['span_seconds']}s  |  Evidence: {a['evidence_count']} events")
            r.append(f"       Sequence    : {' → '.join(a['sequence_matched'])}")
            r.append(f"       Evidence:")
            for ev in a["evidence"][:4]:
                r.append(f"         [{ev.get('source','?')}] {ev.get('event','?')} @ {ev.get('timestamp','')} ({ev.get('tag','')})")
        r.append("\n" + "="*65)
        return "\n".join(r)
