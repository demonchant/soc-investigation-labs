"""
Threat Analyser — Scores threat intelligence items by severity, confidence,
and relevance. Produces risk tiers and recommended response actions.
"""
import logging
logger = logging.getLogger(__name__)

SEVERITY_SCORE = {"critical": 40, "high": 25, "medium": 15, "low": 5}
CONFIDENCE_MULT = {"confirmed": 1.5, "high": 1.2, "medium": 1.0, "low": 0.6}
TYPE_SCORE = {
    "credential_leak": 25, "ransomware_mention": 35, "source_code_leak": 25,
    "ioc_match": 20, "access_sale": 20, "phishing_infrastructure": 15,
    "pii_exposure": 30, "exploit_available": 20
}
RESPONSE = {
    "credential_leak":          "FORCE PASSWORD RESET for all exposed accounts. Enforce MFA immediately. Check for active sessions.",
    "ransomware_mention":       "INITIATE IR PLAN. Verify scope of data theft. Engage legal, comms, and DPO immediately.",
    "source_code_leak":         "REVOKE exposed keys immediately. Audit CloudTrail logs. Rotate all secrets and tokens.",
    "ioc_match":                "BLOCK IOC at perimeter firewall and proxy. Hunt internally for compromise. Pull SIEM logs.",
    "access_sale":              "AUDIT VPN and RDP access logs. Enforce MFA. Reset all remote access credentials.",
    "phishing_infrastructure":  "REGISTER typosquat domain defensively. Block at email gateway. Alert all staff.",
    "pii_exposure":             "NOTIFY DPO immediately. Assess GDPR/regulatory obligations. Begin breach impact assessment.",
    "exploit_available":        "PATCH IMMEDIATELY. Deploy WAF rule as interim control. Monitor for exploitation attempts.",
}


class ThreatAnalyser:
    def analyse(self, items):
        results = []
        for item in items:
            sev_pts = SEVERITY_SCORE.get(item.get("severity", "low"), 5)
            conf_mult = CONFIDENCE_MULT.get(item.get("confidence", "low"), 0.6)
            type_pts = TYPE_SCORE.get(item.get("type", ""), 10)
            score = min(round((sev_pts + type_pts) * conf_mult), 100)

            if score >= 75:
                tier = "CRITICAL"
            elif score >= 55:
                tier = "HIGH"
            elif score >= 35:
                tier = "MEDIUM"
            else:
                tier = "LOW"

            results.append({
                **item,
                "risk_score": score,
                "risk_tier": tier,
                "recommended_response": RESPONSE.get(item.get("type", ""), "Investigate and assess impact.")
            })

        return sorted(results, key=lambda x: x["risk_score"], reverse=True)
