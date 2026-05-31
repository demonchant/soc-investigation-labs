"""Phishing Analysis Report Generator."""
from datetime import datetime

VERDICT_LABEL = {
    "PHISHING":"[PHISHING]","SUSPICIOUS":"[SUSPICIOUS]",
    "LOW_RISK":"[LOW RISK]","CLEAN":"[CLEAN]"
}

class ReportGenerator:
    def generate(self, results):
        r = []
        phishing = sum(1 for x in results if x["verdict"]=="PHISHING")
        suspicious = sum(1 for x in results if x["verdict"]=="SUSPICIOUS")
        clean = sum(1 for x in results if x["verdict"]=="CLEAN")
        r.append("=" * 65)
        r.append("  PHISHING EMAIL ANALYSIS REPORT")
        r.append(f"  Generated : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        r.append(f"  Analysed  : {len(results)} email(s)  |  {phishing} Phishing  |  {suspicious} Suspicious  |  {clean} Clean")
        r.append("=" * 65)
        for res in sorted(results, key=lambda x: x["final_score"], reverse=True):
            lbl = VERDICT_LABEL.get(res["verdict"],"[?]")
            r.append(f"\n  {lbl} [{res['email_id']}] Score: {res['final_score']}/100")
            r.append(f"    From     : {res['from']}")
            r.append(f"    Subject  : {res['subject']}")
            r.append(f"    Verdict  : {res['verdict']} ({res['confidence']} confidence)")
            r.append(f"    Action   : {res['recommended_action']}")
            r.append(f"    Findings :")
            for f in res["header_findings"] + res["content_findings"]:
                r.append(f"      [{f['check']}] {f['result']} (+{f['score']}pts) — {f['detail']}")
        r.append("\n" + "=" * 65)
        return "\n".join(r)
