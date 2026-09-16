import logging
from collections import defaultdict
logger = logging.getLogger(__name__)

class AwarenessAnalyser:
    def analyse(self, simulations, training):
        return {
            "campaign_metrics":    self._campaigns(simulations),
            "department_risk":     self._dept_risk(simulations),
            "high_risk_employees": self._high_risk(training),
            "training_gaps":       self._gaps(training),
            "trend_analysis":      self._trend(simulations),
            "programme_health":    self._health(simulations, training),
        }

    def _campaigns(self, sims):
        metrics = []
        for s in sims:
            sent = s.get("emails_sent",1)
            clicked  = s.get("links_clicked",0) + s.get("attachments_opened",0)
            submitted = s.get("credentials_submitted",0)
            reported  = s.get("reported_suspicious",0)
            cr = round(clicked/sent*100,1)
            metrics.append({
                "campaign_id": s["campaign_id"], "name": s["name"],
                "emails_sent": sent,
                "click_rate_pct":   cr,
                "submit_rate_pct":  round(submitted/sent*100,1),
                "report_rate_pct":  round(reported/sent*100,1),
                "risk_level": "CRITICAL" if cr>15 else "HIGH" if cr>5 else "MEDIUM" if cr>2 else "LOW",
                "repeat_clickers": s.get("repeat_clickers",[]),
            })
        return metrics

    def _dept_risk(self, sims):
        totals = defaultdict(lambda: {"sent":0,"clicked":0,"submitted":0,"reported":0})
        for s in sims:
            for dept, stats in s.get("department_breakdown",{}).items():
                totals[dept]["sent"]      += stats.get("sent",0)
                totals[dept]["clicked"]   += stats.get("clicked",0)
                totals[dept]["submitted"] += stats.get("submitted",0)
                totals[dept]["reported"]  += stats.get("reported",0)
        result = []
        for dept, t in totals.items():
            sent = t["sent"] or 1
            cr = round(t["clicked"]/sent*100,1)
            sr = round(t["submitted"]/sent*100,1)
            rr = round(t["reported"]/sent*100,1)
            score = min(round(cr*3+sr*5),100)
            result.append({"department":dept,"click_rate_pct":cr,"submit_rate_pct":sr,
                "report_rate_pct":rr,"risk_score":score,
                "risk_level":"CRITICAL" if score>60 else "HIGH" if score>35 else "MEDIUM" if score>15 else "LOW"})
        return sorted(result, key=lambda x: -x["risk_score"])

    def _high_risk(self, training):
        hr = []
        for emp in training:
            if emp.get("repeat_offender") or emp.get("risk_score",0)>70:
                hr.append({
                    "employee": emp["employee"], "department": emp["department"],
                    "risk_score": emp["risk_score"],
                    "repeat_offender": emp.get("repeat_offender"),
                    "phishing_complete": emp.get("phishing_awareness_complete"),
                    "basics_complete": emp.get("security_basics_complete"),
                    "action": "MANDATORY TRAINING" if emp.get("repeat_offender") else "TRAINING RECOMMENDED",
                })
        return sorted(hr, key=lambda x: -x["risk_score"])

    def _gaps(self, training):
        total = len(training) or 1
        phish_done = sum(1 for e in training if e.get("phishing_awareness_complete"))
        basic_done = sum(1 for e in training if e.get("security_basics_complete"))
        both_missing = [e["employee"] for e in training
                        if not e.get("phishing_awareness_complete") and not e.get("security_basics_complete")]
        return {
            "phishing_completion_pct": round(phish_done/total*100,1),
            "basics_completion_pct":   round(basic_done/total*100,1),
            "both_modules_incomplete": both_missing,
        }

    def _trend(self, sims):
        if len(sims) < 2: return {"note":"Need 2+ campaigns for trend analysis."}
        rates = [round((s.get("links_clicked",0)+s.get("attachments_opened",0))/s.get("emails_sent",1)*100,1) for s in sims]
        improving = all(rates[i]>=rates[i+1] for i in range(len(rates)-1))
        worsening = all(rates[i]<=rates[i+1] for i in range(len(rates)-1))
        return {
            "campaign_click_rates": [{"id":s["campaign_id"],"rate":r} for s,r in zip(sims,rates)],
            "overall_trend": "IMPROVING" if improving else "WORSENING" if worsening else "MIXED",
            "first_rate": rates[0], "latest_rate": rates[-1],
            "change_pct": round(rates[-1]-rates[0],1),
        }

    def _health(self, sims, training):
        latest = sims[-1] if sims else {}
        sent = latest.get("emails_sent",1)
        clicked  = latest.get("links_clicked",0)+latest.get("attachments_opened",0)
        reported = latest.get("reported_suspicious",0)
        cr = round(clicked/sent*100,1)
        rr = round(reported/sent*100,1)
        total = len(training)
        both_done = sum(1 for e in training
                        if e.get("phishing_awareness_complete") and e.get("security_basics_complete"))
        train_pct = round(both_done/total*100,1) if total else 0
        score = 0
        if cr<5: score+=30
        elif cr<15: score+=15
        if rr>30: score+=30
        elif rr>15: score+=15
        if train_pct>90: score+=40
        elif train_pct>70: score+=20
        return {
            "programme_maturity": "ADVANCED" if score>=80 else "DEVELOPING" if score>=50 else "INITIAL",
            "health_score": score,
            "latest_click_rate_pct": cr,
            "latest_report_rate_pct": rr,
            "training_completion_pct": train_pct,
            "campaigns_run": len(sims),
        }
