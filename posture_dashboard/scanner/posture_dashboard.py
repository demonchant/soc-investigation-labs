"""
Security Posture Dashboard Generator
Aggregates findings from multiple security tools into a unified posture
score per domain (identity, network, endpoint, cloud, detection),
tracks trends, and generates an executive-readable risk narrative.
"""
import logging
logger = logging.getLogger(__name__)

MITRE = {
    "identity":  "T1078 - Valid Accounts (Identity Posture)",
    "network":   "T1071 - Application Layer Protocol (Network Posture)",
    "endpoint":  "T1059 - Command and Scripting Interpreter (Endpoint Posture)",
    "cloud":     "T1078.004 - Cloud Accounts (Cloud Posture)",
    "detection": "Detection Engineering - Detection Program Posture",
}

DOMAIN_WEIGHTS = {
    "identity": 0.25, "network": 0.20, "endpoint": 0.20,
    "cloud": 0.15, "detection": 0.20,
}

SEVERITY_IMPACT = {"critical": 25, "high": 12, "medium": 5, "low": 2}

POSTURE_RATINGS = [
    (90, "EXCELLENT", "Posture is strong. Maintain controls and continue improvement cycle."),
    (75, "GOOD",      "Posture is solid with manageable gaps. Address HIGH findings next sprint."),
    (55, "FAIR",      "Notable weaknesses present. CRITICAL findings require immediate remediation plan."),
    (35, "POOR",      "Significant risk exposure. Executive awareness and dedicated remediation needed."),
    (0,  "CRITICAL",  "Severe risk exposure. Immediate executive escalation required."),
]

DOMAIN_NARRATIVES = {
    "identity": {
        "excellent": "Identity controls are strong. MFA enforced, stale accounts managed, privileged access minimal.",
        "good":      "Identity posture is adequate. Some stale accounts and policy gaps remain.",
        "fair":      "Identity weaknesses present: stale privileged accounts, weak password policies, or delegation issues.",
        "poor":      "Identity posture is weak. Multiple high-risk configurations enable credential theft and escalation.",
        "critical":  "Identity controls are failing. Immediate risk of domain compromise via credential-based attacks.",
    },
    "network": {
        "excellent": "Network perimeter is well-controlled. Minimal exposure, baselines clean.",
        "good":      "Network posture is adequate. Some exposed services and traffic anomalies to address.",
        "fair":      "Network exposure is notable. High-risk ports, traffic spikes, or shadow IT need attention.",
        "poor":      "Network posture is weak. Multiple dangerous exposures and unmonitored traffic patterns.",
        "critical":  "Network is critically exposed. Immediate containment of high-risk services required.",
    },
    "endpoint": {
        "excellent": "Endpoints are well-hardened. Tool abuse detections low, EDR coverage comprehensive.",
        "good":      "Endpoint posture is adequate. Some suspicious tool activity and policy gaps to address.",
        "fair":      "Endpoint weaknesses detected. Suspicious tool abuse and configuration gaps present.",
        "poor":      "Endpoint posture is weak. Active abuse of system tools and insufficient hardening.",
        "critical":  "Endpoints are critically compromised. Active attack tooling detected on multiple hosts.",
    },
    "cloud": {
        "excellent": "Cloud posture is strong. Least-privilege applied, logging enabled, no critical misconfigs.",
        "good":      "Cloud posture is adequate. Some overprivileged roles and minor misconfigurations.",
        "fair":      "Cloud weaknesses present. Overprivileged roles, hardcoded secrets, or logging gaps.",
        "poor":      "Cloud posture is weak. Critical IAM misconfigs and credential exposure risks.",
        "critical":  "Cloud is critically misconfigured. Immediate risk of account takeover or data breach.",
    },
    "detection": {
        "excellent": "Detection program is mature. High TP rates, low noise, good ATT&CK coverage.",
        "good":      "Detection posture is solid. Some noisy rules and coverage gaps to address.",
        "fair":      "Detection gaps present. Significant alert noise and missing coverage for key techniques.",
        "poor":      "Detection is weak. Low TP rates, high analyst burden, major coverage gaps.",
        "critical":  "Detection is failing. Alert fatigue is severe. Attackers can operate largely undetected.",
    },
}


def score_to_rating(score):
    if score >= 90: return "excellent"
    if score >= 75: return "good"
    if score >= 55: return "fair"
    if score >= 35: return "poor"
    return "critical"


class PostureDashboard:
    def __init__(self): self.findings = []

    def generate_all(self, data):
        tool_results  = data.get("tool_results", {})
        historical    = data.get("historical_scores", [])
        domain_scores = self._compute_domain_scores(tool_results)
        overall       = self._compute_overall(domain_scores)
        self._generate_domain_findings(domain_scores, tool_results)
        self._generate_trend_analysis(historical, overall)
        self._generate_executive_summary(domain_scores, overall, data)
        self._generate_roadmap(domain_scores, tool_results)
        return self.findings

    def _f(self, domain, title, sev, detail, mitre, rec):
        self.findings.append({"domain": domain, "title": title, "severity": sev,
            "detail": detail, "mitre_technique": mitre, "recommendation": rec})

    def _compute_domain_scores(self, tool_results):
        scores = {}
        for domain, findings in tool_results.items():
            score = 100
            for f in findings:
                score -= SEVERITY_IMPACT.get(f.get("severity","low").lower(), 2)
            scores[domain] = max(score, 0)
        for domain in DOMAIN_WEIGHTS:
            if domain not in scores:
                scores[domain] = 70
        return scores

    def _compute_overall(self, domain_scores):
        total = sum(domain_scores.get(d, 70) * w for d, w in DOMAIN_WEIGHTS.items())
        return max(min(int(total), 100), 0)

    def _generate_domain_findings(self, domain_scores, tool_results):
        sev_map = {"excellent":"low","good":"low","fair":"medium","poor":"high","critical":"critical"}
        for domain, score in domain_scores.items():
            rating   = score_to_rating(score)
            sev      = sev_map.get(rating, "medium")
            findings = tool_results.get(domain, [])
            crits    = sum(1 for f in findings if f.get("severity")=="critical")
            highs    = sum(1 for f in findings if f.get("severity")=="high")
            narrative= DOMAIN_NARRATIVES.get(domain,{}).get(rating,"Score: {}/100.".format(score))
            self._f(domain.upper(),
                "{} Posture: {}/100 — {}".format(domain.title(), score, rating.upper()),
                sev,
                "{} | {} critical, {} high finding(s).".format(narrative, crits, highs),
                MITRE.get(domain,"Detection Engineering"),
                self._domain_rec(domain, rating, crits, highs))

    def _domain_rec(self, domain, rating, crits, highs):
        if rating in ("excellent","good"):
            return "Maintain controls. Schedule next review in 30 days."
        if crits > 0:
            return "Address {} CRITICAL finding(s) in {} within 48 hours. Assign dedicated owner.".format(
                crits, domain)
        if highs > 0:
            return "Remediate {} HIGH finding(s) in {} within 1 week. Include in next sprint.".format(
                highs, domain)
        return "Review MEDIUM findings in {}. Target next monthly cycle.".format(domain)

    def _generate_trend_analysis(self, historical, current):
        if len(historical) < 2:
            return
        prev  = historical[-1].get("overall_score", current)
        oldest= historical[0].get("overall_score",  current)
        delta = current - prev
        trend = current - oldest

        if delta < -10:
            self._f("TREND",
                "Posture Declining: -{} points from last period".format(abs(delta)), "high",
                "Overall score dropped {} points since last assessment ({} → {}). "
                "Trend over {} periods: {} points.".format(
                    abs(delta), prev, current, len(historical), trend),
                "Detection Engineering - Posture Trend",
                "Identify what changed: new assets, new findings, or unresolved carryover. "
                "Assign remediation owner for declining domains.")
        elif delta > 10:
            self._f("TREND",
                "Posture Improving: +{} points from last period".format(delta), "low",
                "Score improved {} points ({} → {}). Trend: {} points over {} periods.".format(
                    delta, prev, current, trend, len(historical)),
                "Detection Engineering - Posture Trend",
                "Document what drove improvement. Replicate in other domains.")
        elif abs(delta) <= 3:
            self._f("TREND",
                "Posture Stagnant: ±{} points (no meaningful change)".format(abs(delta)), "medium",
                "Score unchanged ({} → {}). Findings opening at same rate as closing.".format(
                    prev, current),
                "Detection Engineering - Posture Trend",
                "Review remediation velocity. Set SLAs per severity to close findings "
                "faster than they open.")

    def _generate_executive_summary(self, domain_scores, overall, data):
        label, action = "UNKNOWN", "N/A"
        for threshold, lbl, act in POSTURE_RATINGS:
            if overall >= threshold:
                label = lbl; action = act; break

        weakest   = sorted(domain_scores.items(), key=lambda x: x[1])[:2]
        strongest = sorted(domain_scores.items(), key=lambda x: -x[1])[:2]

        self._f("EXECUTIVE",
            "Overall Security Posture: {}/100 — {}".format(overall, label),
            "critical" if overall<35 else "high" if overall<55 else "medium" if overall<75 else "low",
            "Organisation posture: {}/100 ({}). "
            "Weakest: {} ({}), {} ({}). Strongest: {} ({}), {} ({}). Period: {}.".format(
                overall, label,
                weakest[0][0].title(),  weakest[0][1],
                weakest[1][0].title() if len(weakest)>1 else "N/A",
                weakest[1][1]         if len(weakest)>1 else "N/A",
                strongest[0][0].title(), strongest[0][1],
                strongest[1][0].title() if len(strongest)>1 else "N/A",
                strongest[1][1]         if len(strongest)>1 else "N/A",
                data.get("assessment_period","current period")),
            "Security Posture Composite Score", action)

    def _generate_roadmap(self, domain_scores, tool_results):
        all_f = [(d, f) for d, findings in tool_results.items() for f in findings]
        sev_rank = {"critical":0,"high":1,"medium":2,"low":3}
        all_f.sort(key=lambda x: (sev_rank.get(x[1].get("severity","low"),9),
                                   domain_scores.get(x[0],50)))
        crits = [(d,f) for d,f in all_f if f.get("severity")=="critical"]
        if crits:
            items = ["{} [{}]: {}".format(d.upper(), f.get("severity","?").upper(),
                     f.get("title","?")[:55]) for d,f in crits[:5]]
            self._f("ROADMAP",
                "Top {} Critical Remediation Items".format(len(crits)), "high",
                "Prioritised critical findings: {}.".format(" | ".join(items)),
                "Security Posture - Remediation Priority",
                "Assign named owner and 48-hour deadline to each. "
                "Re-run posture assessment after each remediation batch.")
