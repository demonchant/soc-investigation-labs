"""
Incident Severity Scoring Engine
Multi-factor severity scoring: asset criticality, kill chain phase,
data sensitivity, blast radius, attacker capability, business context.
Produces reproducible verdicts with analyst mismatch detection.
"""
import logging
logger = logging.getLogger(__name__)

MITRE = {
    "triage":  "Incident Response - Consistent Triage Methodology",
    "impact":  "Incident Response - Impact Assessment",
    "priority":"Incident Response - Prioritization Framework",
}

ASSET_CRITICALITY = {
    "tier0": 40, "tier1": 30, "tier2": 20, "tier3": 10, "tier4": 5,
}
KILL_CHAIN_SCORES = {
    "reconnaissance":5,"initial_access":15,"execution":20,"persistence":25,
    "privilege_escalation":30,"defense_evasion":20,"credential_access":30,
    "discovery":10,"lateral_movement":35,"collection":30,
    "command_and_control":25,"exfiltration":40,"impact":45,
}
DATA_SENSITIVITY = {
    "none":0,"internal":5,"confidential":15,"pii":25,
    "financial":25,"health":30,"trade_secret":35,"regulated":30,
}
ATTACKER_CAPABILITY = {
    "script_kiddie":5,"opportunistic":10,"competent":20,"advanced":30,"nation_state":40,
}
BUSINESS_CONTEXT = {
    "outside_hours":5,"incident_ongoing":10,"executive_involved":10,
    "regulatory_scope":15,"media_risk":10,"sla_breach_risk":5,
}
SEVERITY_THRESHOLDS = [
    (85,"critical","Immediate response. All-hands. Executive notification."),
    (65,"high",    "Urgent response within 1 hour. Senior analyst lead."),
    (40,"medium",  "Response within 4 hours. Standard IR process."),
    (20,"low",     "Response within 24 hours. Queue for next analyst."),
    (0, "info",    "Log and monitor. No immediate action required."),
]
CONFIDENCE_MULT = {"confirmed":1.0,"suspected":0.75,"possible":0.5,"unlikely":0.25}
SEV_ORDER = ["info","low","medium","high","critical"]

class SeverityScoringEngine:
    def __init__(self): self.findings = []

    def score_all(self, data):
        for inc in data.get("incidents",[]): self._score(inc)
        return self.findings

    def _f(self, inc_id, title, sev, detail, mitre, rec, score=0):
        self.findings.append({"incident_id":inc_id,"title":title,"severity":sev,
            "composite_score":score,"detail":detail,"mitre_technique":mitre,"recommendation":rec})

    def _score(self, inc):
        inc_id = inc.get("incident_id","?")
        scores = {}
        scores["asset_criticality"]  = ASSET_CRITICALITY.get(inc.get("asset_tier","tier3"),10)
        scores["kill_chain_phase"]   = KILL_CHAIN_SCORES.get(inc.get("kill_chain_phase","initial_access").lower(),10)
        scores["data_sensitivity"]   = DATA_SENSITIVITY.get(inc.get("data_sensitivity","internal").lower(),5)
        scores["blast_radius"]       = self._blast(inc.get("affected_assets_count",1))
        scores["attacker_capability"]= ATTACKER_CAPABILITY.get(inc.get("attacker_capability","opportunistic").lower(),10)
        ctx_score = sum(v for k,v in BUSINESS_CONTEXT.items() if inc.get(k,False))
        scores["business_context"]   = ctx_score
        confidence = inc.get("confidence","suspected").lower()
        mult = CONFIDENCE_MULT.get(confidence,0.75)
        base  = sum(v for k,v in scores.items() if k != "business_context")
        total = min(int(base * mult) + ctx_score, 100)
        sev_label, sev_action = "info","Log and monitor."
        for threshold, label, action in SEVERITY_THRESHOLDS:
            if total >= threshold:
                sev_label = label; sev_action = action; break
        breakdown = " | ".join("{}: {}".format(k.replace("_"," ").title(),v)
                               for k,v in scores.items())
        self._f(inc_id,
            "Severity: {} — {} ({}/100)".format(inc_id, sev_label.upper(), total),
            sev_label,
            "Incident '{}' scored {}/100 → {}. {}. Confidence: {} (×{:.2f}).".format(
                inc.get("title","?"), total, sev_label.upper(), breakdown, confidence, mult),
            MITRE["triage"], sev_action, total)
        # Mismatch detection
        analyst_sev = inc.get("analyst_assigned_severity","").lower()
        if analyst_sev and analyst_sev in SEV_ORDER and sev_label in SEV_ORDER:
            a_idx = SEV_ORDER.index(analyst_sev)
            m_idx = SEV_ORDER.index(sev_label)
            gap   = abs(a_idx - m_idx)
            if gap >= 2:
                direction = "UNDER" if a_idx < m_idx else "OVER"
                self._f(inc_id,
                    "Severity Mismatch: Analyst {} vs Model {} ({} by {} levels)".format(
                        analyst_sev.upper(), sev_label.upper(), direction, gap),
                    "medium",
                    "Analyst assigned {} but model scores {}. Gap of {} severity levels. "
                    "Top scoring factors: {}.".format(
                        analyst_sev.upper(), sev_label.upper(), gap,
                        ", ".join("{} ({})".format(k.replace("_"," "),v)
                                  for k,v in sorted(scores.items(),key=lambda x:-x[1])[:3])),
                    MITRE["priority"],
                    "Review scoring inputs with incident lead. Document rationale for any override. "
                    "Consistent mismatches indicate model calibration may need adjustment.")

    def _blast(self, n):
        if n<=0: return 0
        if n==1: return 5
        if n<=5: return 10
        if n<=20: return 20
        if n<=100: return 30
        return 40
