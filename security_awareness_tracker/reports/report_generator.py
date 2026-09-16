from datetime import datetime

class ReportGenerator:
    def generate(self, results):
        health = results.get("programme_health",{})
        r = []
        r.append("="*65)
        r.append("  SECURITY AWARENESS PROGRAMME REPORT")
        r.append("  Generated : " + datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
        r.append("  Maturity  : {}  |  Health Score: {}/100".format(
            health.get("programme_maturity","?"), health.get("health_score",0)))
        r.append("="*65)
        r.append("")
        r.append("  CAMPAIGN PERFORMANCE")
        r.append("")
        r.append("  {:<30} {:>5} {:>7} {:>8} {:>8}  Risk".format("Campaign","Sent","Click%","Submit%","Report%"))
        r.append("  " + "-"*63)
        for m in results.get("campaign_metrics",[]):
            r.append("  {:<30} {:>5} {:>6}% {:>7}% {:>7}%  {}".format(
                m["name"][:30], m["emails_sent"],
                m["click_rate_pct"], m["submit_rate_pct"],
                m["report_rate_pct"], m["risk_level"]))
        r.append("")
        r.append("  DEPARTMENT RISK RANKING")
        r.append("")
        for d in results.get("department_risk",[]):
            flag = " << PRIORITY" if d["risk_score"]>35 else ""
            r.append("  {:<16} Click:{:>5}%  Submit:{:>5}%  Report:{:>5}%  Score:{:>4}  {}{}".format(
                d["department"], d["click_rate_pct"], d["submit_rate_pct"],
                d["report_rate_pct"], d["risk_score"], d["risk_level"], flag))
        r.append("")
        r.append("  HIGH-RISK EMPLOYEES")
        r.append("")
        for emp in results.get("high_risk_employees",[]):
            r.append("  [{}] {} ({})  Score: {}/100  Repeat: {}".format(
                emp["action"], emp["employee"], emp["department"],
                emp["risk_score"], emp["repeat_offender"]))
            r.append("    Phishing: {}  |  Basics: {}".format(
                "DONE" if emp["phishing_complete"] else "OUTSTANDING",
                "DONE" if emp["basics_complete"] else "OUTSTANDING"))
        r.append("")
        gaps = results.get("training_gaps",{})
        r.append("  TRAINING COMPLETION")
        r.append("")
        r.append("  Phishing Awareness : {}%".format(gaps.get("phishing_completion_pct",0)))
        r.append("  Security Basics    : {}%".format(gaps.get("basics_completion_pct",0)))
        if gaps.get("both_modules_incomplete"):
            r.append("  Both Incomplete    : {}".format(", ".join(gaps["both_modules_incomplete"])))
        r.append("")
        trend = results.get("trend_analysis",{})
        r.append("  TREND: {}  ({}% → {}%  change: {}%)".format(
            trend.get("overall_trend","?"), trend.get("first_rate","?"),
            trend.get("latest_rate","?"), trend.get("change_pct","?")))
        r.append("")
        r.append("  HEALTH: {}/100 [{}]  Click: {}%  Report: {}%  Training: {}%".format(
            health.get("health_score",0), health.get("programme_maturity","?"),
            health.get("latest_click_rate_pct","?"), health.get("latest_report_rate_pct","?"),
            health.get("training_completion_pct","?")))
        r.append("")
        r.append("="*65)
        return "\n".join(r)
