"""Report Generator — Threat actor profiling and IOC summary report."""
from datetime import datetime


class ReportGenerator:
    def generate(self, profiles, iocs):
        total_iocs = sum(len(v) for v in iocs.values())
        r = []
        r.append("=" * 65)
        r.append("  HONEYPOT THREAT ACTOR PROFILING REPORT")
        r.append("  Generated   : " + datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
        r.append("  Attackers   : " + str(len(profiles)))
        r.append("  IOCs Found  : " + str(total_iocs))
        r.append("=" * 65)
        r.append("\n  ATTACKER PROFILES\n")

        for ip, p in profiles.items():
            score = p["threat_score"]
            tier = "CRITICAL" if score >= 70 else "HIGH" if score >= 45 else "MEDIUM"
            r.append("  > " + ip + " [" + p["country"] + "] — Score: " + str(score) + "/100 [" + tier + "]")
            r.append("    Services Targeted : " + ", ".join(p["services_targeted"]))
            r.append("    Interactions      : " + str(p["interaction_count"]))
            r.append("    TTPs Identified   : " + str(len(p["ttps"])))
            for ttp in p["ttps"]:
                r.append("      * " + ttp["id"] + " — " + ttp["name"])
            if p["credentials_tried"]:
                r.append("    Credentials Tried : " + ", ".join(p["credentials_tried"][:5]))
            if p["commands_executed"]:
                r.append("    Commands Run      : " + str(len(p["commands_executed"])))
                for cmd in p["commands_executed"][:3]:
                    r.append("      $ " + cmd[:80])
            r.append("")

        r.append("  IOC SUMMARY\n")
        for ioc_type, values in iocs.items():
            if values:
                label = ioc_type.upper().replace("_", " ")
                r.append("  " + label + ":")
                for v in values[:5]:
                    r.append("    - " + str(v))
                r.append("")

        r.append("=" * 65)
        return "\n".join(r)
