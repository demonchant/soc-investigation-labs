"""
Risk Scorer — Combines header and content scores into a final phishing verdict.
"""
class RiskScorer:
    def score(self, email, header_findings, header_score, content_findings, content_score):
        # Weighted combination: header 40%, content 60%
        combined = round(header_score * 0.4 + content_score * 0.6)
        total_findings = len(header_findings) + len(content_findings)

        if combined >= 70:
            verdict = "PHISHING"
            confidence = "HIGH"
        elif combined >= 45:
            verdict = "SUSPICIOUS"
            confidence = "MEDIUM"
        elif combined >= 20:
            verdict = "LOW_RISK"
            confidence = "LOW"
        else:
            verdict = "CLEAN"
            confidence = "HIGH"

        return {
            "email_id": email.get("id"),
            "subject": email.get("subject",""),
            "from": email.get("from",""),
            "verdict": verdict,
            "confidence": confidence,
            "final_score": combined,
            "header_score": header_score,
            "content_score": content_score,
            "total_findings": total_findings,
            "header_findings": header_findings,
            "content_findings": content_findings,
            "recommended_action": self._action(verdict)
        }

    def _action(self, verdict):
        return {
            "PHISHING": "QUARANTINE immediately. Block sender domain. Submit URLs for takedown. Alert user.",
            "SUSPICIOUS": "Hold for analyst review. Sandbox any attachments. Notify recipient.",
            "LOW_RISK": "Deliver with warning banner. Log for trend analysis.",
            "CLEAN": "Deliver normally."
        }.get(verdict, "Review manually.")
