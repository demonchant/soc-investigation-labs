"""Dark Web and Threat Feed Report Generator."""
from datetime import datetime

TIER_LABEL = {
    "CRITICAL": "[CRITICAL]", "HIGH": "[HIGH]",
    "MEDIUM": "[MEDIUM]", "LOW": "[LOW]"
}


class ReportGenerator:
    def generate(self, items):
        c = sum(1 for i in items if i["risk_tier"] == "CRITICAL")
        h = sum(1 for i in items if i["risk_tier"] == "HIGH")
        r = []
        r.append("=" * 68)
        r.append("  DARK WEB AND THREAT FEED INTELLIGENCE REPORT")
        r.append("  Generated  : " + datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
        r.append("  Items      : " + str(len(items)) + "  |  " + str(c) + " Critical  |  " + str(h) + " High")
        r.append("=" * 68)

        for i, item in enumerate(items, 1):
            lbl = TIER_LABEL.get(item["risk_tier"], "[?]")
            r.append("")
            r.append("  [" + str(i) + "] " + lbl + " [" + item["id"] + "] " + item["title"])
            r.append("       Feed        : " + item["feed"] + "  |  Source: " + item["source"])
            r.append("       Type        : " + item["type"] + "  |  Confidence: " + item["confidence"])
            r.append("       Threat Actor: " + str(item.get("threat_actor", "unknown")))
            r.append("       Risk Score  : " + str(item["risk_score"]) + "/100")
            r.append("       Data Exposed: " + ", ".join(item.get("data_types", [])))
            if item.get("ioc"):
                r.append("       IOC         : " + str(item["ioc"]))
            r.append("       Summary     : " + item["description"][:120])
            r.append("       Response    : " + item["recommended_response"])

        r.append("")
        r.append("=" * 68)
        return "\n".join(r)
