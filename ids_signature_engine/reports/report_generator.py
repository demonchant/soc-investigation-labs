"""IDS Alert Report Generator."""
from datetime import datetime
SEV_ORDER = {"critical":0,"high":1,"medium":2,"low":3}
SEV_LABEL = {"critical":"[CRITICAL]","high":"[HIGH]","medium":"[MEDIUM]","low":"[LOW]"}

class ReportGenerator:
    def generate(self, alerts, packet_count, sig_count):
        alerts = sorted(alerts, key=lambda a: SEV_ORDER.get(a["severity"],9))
        c = sum(1 for a in alerts if a["severity"]=="critical")
        h = sum(1 for a in alerts if a["severity"]=="high")
        r = []
        r.append("="*65)
        r.append("  INTRUSION DETECTION SYSTEM — ALERT REPORT")
        r.append("  Generated  : " + datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
        r.append("  Packets    : " + str(packet_count) + "  |  Signatures: " + str(sig_count))
        r.append("  Alerts     : " + str(len(alerts)) + "  |  " + str(c) + " Critical  |  " + str(h) + " High")
        r.append("="*65)
        for i, a in enumerate(alerts,1):
            lbl = SEV_LABEL.get(a["severity"],"[?]")
            r.append("")
            r.append("  [" + str(i) + "] " + lbl + " [" + a["sig_id"] + "] " + a["sig_name"])
            r.append("       Packet   : " + a["packet_id"] + " | " + a["timestamp"])
            r.append("       Src IP   : " + a["src_ip"] + "  →  " + a["dst_ip"] + ":" + str(a.get("dst_port","")))
            r.append("       MITRE    : " + a["mitre"])
            r.append("       Category : " + a["category"])
            r.append("       Detail   : " + a["description"])
            r.append("       Payload  : " + a["payload_snip"][:80])
        r.append("")
        r.append("="*65)
        return "\n".join(r)
