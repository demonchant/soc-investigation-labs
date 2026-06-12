from datetime import datetime
SEV_ORDER = {"critical":0,"high":1,"medium":2,"low":3}
SEV_LABEL = {"critical":"[CRITICAL]","high":"[HIGH]","medium":"[MEDIUM]","low":"[LOW]"}

class ReportGenerator:
    def generate(self, alerts, event_count):
        alerts = sorted(alerts, key=lambda a: SEV_ORDER.get(a["severity"],9))
        c = sum(1 for a in alerts if a["severity"]=="critical")
        h = sum(1 for a in alerts if a["severity"]=="high")
        r = []
        r.append("="*65)
        r.append("  DNS SECURITY MONITOR REPORT")
        r.append("  Generated : " + datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
        r.append("  Events    : {}  |  Alerts: {}  |  {} Critical  |  {} High".format(event_count,len(alerts),c,h))
        r.append("="*65)
        for i,a in enumerate(alerts,1):
            lbl = SEV_LABEL.get(a["severity"],"[?]")
            r.append("")
            r.append("  [{}] {} {}".format(i,lbl,a["title"]))
            r.append("       Src IP : " + a["src_ip"])
            r.append("       MITRE  : " + a["mitre_technique"])
            for k,v in a.get("evidence",{}).items():
                r.append("       {:<18}: {}".format(str(k), str(v)[:70]))
        r.append("")
        r.append("="*65)
        return "\n".join(r)
