"""
Triage Engine — Scores and prioritises alerts by severity, host criticality,
and technique chaining. Groups related alerts into incident chains.
"""
import logging
from collections import defaultdict

logger = logging.getLogger(__name__)

SEV_SCORE = {"critical": 40, "high": 25, "medium": 10, "low": 3}

CRITICAL_HOSTS = {"DC-01", "DC-02", "EXCHANGE-01", "FILESERVER-01"}

HIGH_IMPACT_TECHNIQUES = {
    "T1003.001", "T1490", "T1059.001", "T1105",
    "T1547.001", "T1566.001", "T1021.003"
}


class TriageEngine:
    def prioritise(self, alerts):
        scored = []
        for a in alerts:
            score = SEV_SCORE.get(a["severity"], 0)
            if a.get("host") in CRITICAL_HOSTS:
                score += 20
            tid = a.get("mitre_technique","").split(" ")[0]
            if tid in HIGH_IMPACT_TECHNIQUES:
                score += 15
            scored.append({**a, "triage_score": min(score, 100)})

        scored.sort(key=lambda x: x["triage_score"], reverse=True)

        # Group by host for incident chaining
        by_host = defaultdict(list)
        for a in scored:
            by_host[a.get("host","unknown")].append(a)

        chains = []
        for host, host_alerts in by_host.items():
            if len(host_alerts) >= 2:
                techniques = [a["mitre_technique"].split(" ")[0] for a in host_alerts]
                chains.append({
                    "host": host,
                    "alert_count": len(host_alerts),
                    "techniques": techniques,
                    "max_score": max(a["triage_score"] for a in host_alerts),
                    "verdict": "INCIDENT" if len(host_alerts) >= 3 else "SUSPICIOUS"
                })

        return scored, chains
