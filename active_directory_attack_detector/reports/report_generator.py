"""AD Attack Report Generator."""
from datetime import datetime

SEV_ORDER = {"critical":0,"high":1,"medium":2}
SEV_LABEL = {"critical":"[CRITICAL]","high":"[HIGH]","medium":"[MEDIUM]"}

class ReportGenerator:
    def generate(self, alerts):
        if not alerts: return "[OK] No AD attacks detected."
        alerts = sorted(alerts, key=lambda a: SEV_ORDER.get(a["severity"],9))
        c = sum(1 for a in alerts if a["severity"]=="critical")
        h = sum(1 for a in alerts if a["severity"]=="high")
        r = []
        r.append("="*65)
        r.append("  ACTIVE DIRECTORY ATTACK DETECTION REPORT")
        r.append(f"  Generated : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        r.append(f"  Alerts    : {len(alerts)}  |  {c} Critical  |  {h} High")
        r.append("="*65)
        for i,a in enumerate(alerts,1):
            lbl = SEV_LABEL.get(a["severity"],"[?]")
            r.append(f"\n  [{i}] {lbl} {a['title']}")
            r.append(f"       User    : {a['user']}")
            r.append(f"       Src IP  : {a['src_ip']}")
            r.append(f"       MITRE   : {a['mitre_technique']}")
            for k,v in a.get("evidence",{}).items():
                r.append(f"       {str(k):<20}: {str(v)[:70]}")
        r.append("\n"+"="*65)
        return "\n".join(r)
