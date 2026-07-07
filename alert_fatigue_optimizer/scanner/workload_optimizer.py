"""
Alert Fatigue & SOC Workload Optimizer
Analyzes SIEM alert history to quantify analyst burden:
TP/FP rates, MTTD/MTTR per rule, noise generators,
automation candidates, and tuning roadmap ranked by hours-saved.
"""
import statistics, logging
from collections import defaultdict
logger = logging.getLogger(__name__)

MITRE = {
    "noise":    "Detection Engineering - False Positive Reduction",
    "coverage": "Detection Engineering - True Positive Rate",
    "sla":      "Incident Response - MTTD/MTTR Optimization",
    "burn":     "SOC Operations - Analyst Burnout Risk",
    "automate": "SOAR - Automation Opportunity",
}

TRIAGE_MINUTES   = {"critical": 20, "high": 12, "medium": 7, "low": 3}
ANALYST_CAP_MIN  = 480   # 8-hour day in minutes

class WorkloadOptimizer:
    def __init__(self): self.findings = []

    def analyze_all(self, data):
        alerts   = data.get("alert_history", [])
        analysts = data.get("analyst_count", 2)
        rules    = self._aggregate(alerts)
        self._flag_noise(rules, analysts)
        self._flag_zero_tp(rules)
        self._analyze_mttd_mttr(rules)
        self._detect_burnout(rules, analysts)
        self._identify_automation(rules)
        self._summary(rules, analysts)
        return self.findings

    def _f(self, rule_id, title, sev, detail, mitre, rec, hours_saved=0.0):
        self.findings.append({
            "rule_id": rule_id, "title": title, "severity": sev,
            "detail": detail, "mitre_technique": mitre,
            "recommendation": rec,
            "analyst_hours_saved_per_day": round(hours_saved, 2)
        })

    def _aggregate(self, alerts):
        rules = defaultdict(lambda: {
            "alerts": 0, "true_positives": 0, "false_positives": 0,
            "auto_closed": 0, "tickets": 0,
            "mttd": [], "mttr": [],
            "sev_dist": defaultdict(int),
            "analyst_touches": 0,
        })
        for a in alerts:
            rid = a.get("rule_id", "UNKNOWN")
            d   = rules[rid]
            d["alerts"] += 1
            d["sev_dist"][a.get("severity", "medium")] += 1
            outcome = a.get("outcome", "").lower()
            if outcome == "true_positive":
                d["true_positives"] += 1
                d["tickets"] += 1
            elif outcome == "false_positive":
                d["false_positives"] += 1
            elif outcome == "auto_closed":
                d["auto_closed"] += 1
            if a.get("analyst_touched"):
                d["analyst_touches"] += 1
            if a.get("mttd_minutes"):
                d["mttd"].append(float(a["mttd_minutes"]))
            if a.get("mttr_minutes"):
                d["mttr"].append(float(a["mttr_minutes"]))
        return dict(rules)

    def _dominant_sev(self, sev_dist):
        return max(sev_dist, key=sev_dist.get, default="medium")

    def _triage_hours(self, d):
        sev = self._dominant_sev(d["sev_dist"])
        return (d["analyst_touches"] * TRIAGE_MINUTES.get(sev, 7)) / 60

    # ── Noise generators ────────────────────────────────────────────────────
    def _flag_noise(self, rules, analysts):
        team_cap = analysts * ANALYST_CAP_MIN
        for rid, d in rules.items():
            total = d["alerts"]
            if total < 10:
                continue
            fp_rate      = d["false_positives"] / total
            hours_wasted = self._triage_hours(d)
            cap_pct      = (d["analyst_touches"] * TRIAGE_MINUTES.get(
                self._dominant_sev(d["sev_dist"]), 7)) / team_cap * 100

            if fp_rate >= 0.70:
                self._f(rid,
                    "High-Noise Rule: {} ({:.0%} FP, {:.1f}h/day wasted)".format(
                        rid, fp_rate, hours_wasted),
                    "critical",
                    "Rule '{}' fires with {:.0%} false positive rate — "
                    "{:.1f} analyst-hours/day consumed ({:.0f}% of team capacity). "
                    "Total: {} alerts, {} FPs.".format(
                        rid, fp_rate, hours_wasted, cap_pct,
                        total, d["false_positives"]),
                    MITRE["noise"],
                    "IMMEDIATE TUNING: add exclusion conditions for known-good activity, "
                    "raise threshold, or demote to informational until fixed. "
                    "Reclaims {:.1f} analyst-hours/day.".format(hours_wasted),
                    hours_wasted)

            elif fp_rate >= 0.40:
                self._f(rid,
                    "Noisy Rule: {} ({:.0%} FP, {:.1f}h/day)".format(
                        rid, fp_rate, hours_wasted),
                    "high",
                    "Rule '{}' has {:.0%} FP rate — "
                    "{:.1f} analyst-hours/day lost to triage.".format(
                        rid, fp_rate, hours_wasted),
                    MITRE["noise"],
                    "Schedule tuning sprint. Add context-based exclusions. "
                    "Target: FP rate < 20% within 2 weeks.",
                    hours_wasted)

    # ── Zero TP ─────────────────────────────────────────────────────────────
    def _flag_zero_tp(self, rules):
        for rid, d in rules.items():
            if d["alerts"] >= 20 and d["true_positives"] == 0:
                self._f(rid,
                    "Zero True Positives: {} ({} alerts fired, 0 TPs)".format(
                        rid, d["alerts"]),
                    "high",
                    "Rule '{}' fired {} times with ZERO confirmed true positives — "
                    "consuming analyst time without ever catching anything real.".format(
                        rid, d["alerts"]),
                    MITRE["coverage"],
                    "Disable or demote to informational. Redesign detection logic "
                    "from scratch with tighter conditions before re-enabling.")

    # ── MTTD / MTTR ──────────────────────────────────────────────────────────
    def _analyze_mttd_mttr(self, rules):
        for rid, d in rules.items():
            if d["mttd"] and statistics.mean(d["mttd"]) > 60:
                avg = statistics.mean(d["mttd"])
                self._f(rid,
                    "High MTTD: {} ({:.0f} min avg)".format(rid, avg), "medium",
                    "Rule '{}' averages {:.0f}-minute Mean Time to Detect — "
                    "slow detection increases dwell time and attacker opportunity.".format(
                        rid, avg),
                    MITRE["sla"],
                    "Check log ingestion pipeline latency. Verify rule runs on "
                    "streaming vs batch schedule. Target MTTD < 5 min for critical techniques.")

            if d["mttr"] and statistics.mean(d["mttr"]) > 240:
                avg = statistics.mean(d["mttr"])
                self._f(rid,
                    "High MTTR: {} ({:.0f} min / {:.1f}h avg)".format(
                        rid, avg, avg / 60),
                    "medium",
                    "Rule '{}' averages {:.0f}-minute resolution time — "
                    "slow resolution increases incident impact and queue depth.".format(
                        rid, avg),
                    MITRE["sla"],
                    "Create a standardized runbook for this alert type. "
                    "Automate common resolution actions via SOAR. "
                    "Target MTTR < 60 min for high-severity alerts.")

    # ── Burnout risk ─────────────────────────────────────────────────────────
    def _detect_burnout(self, rules, analysts):
        total_touch_min = sum(
            d["analyst_touches"] * TRIAGE_MINUTES.get(self._dominant_sev(d["sev_dist"]),7)
            for d in rules.values()
        )
        total_alerts = sum(d["alerts"] for d in rules.values())
        total_tp     = sum(d["true_positives"] for d in rules.values())
        team_cap     = analysts * ANALYST_CAP_MIN
        cap_pct      = total_touch_min / team_cap * 100 if team_cap else 0
        signal_ratio = total_tp / total_alerts if total_alerts else 0

        if cap_pct > 80:
            self._f("TEAM",
                "Analyst Capacity Critical: {:.0f}% of team time consumed by triage".format(
                    cap_pct),
                "critical",
                "Team of {} analysts spends {:.0f}% of available time triaging alerts. "
                "Volume: {} | TPs: {} ({:.0%} signal). "
                "No capacity for threat hunting, tuning, or proactive work.".format(
                    analysts, cap_pct, total_alerts, total_tp, signal_ratio),
                MITRE["burn"],
                "Emergency noise reduction required. Suppress or tune top 3 noise generators "
                "immediately. Add analysts or implement SOAR automation.")

        elif cap_pct > 60:
            self._f("TEAM",
                "Analyst Capacity Warning: {:.0f}% utilized".format(cap_pct), "high",
                "Alert triage consumes {:.0f}% of team capacity — "
                "limited headroom for proactive security work.".format(cap_pct),
                MITRE["burn"],
                "Prioritize tuning highest-volume noisy rules. "
                "Target 40-50% capacity for triage; remainder for hunting and improvement.")

    # ── Automation candidates ────────────────────────────────────────────────
    def _identify_automation(self, rules):
        for rid, d in rules.items():
            total  = d["alerts"]
            tp_rate = d["true_positives"] / total if total else 0
            auto_pct = d["auto_closed"] / total if total else 0

            if total >= 50 and tp_rate >= 0.80:
                hours = self._triage_hours(d)
                self._f(rid,
                    "Automation Opportunity: {} ({:.0%} TP, {} alerts/period)".format(
                        rid, tp_rate, total),
                    "low",
                    "Rule '{}' fires frequently ({}) with {:.0%} TP rate — "
                    "highly consistent signal, ideal for automated response.".format(
                        rid, total, tp_rate),
                    MITRE["automate"],
                    "Build SOAR playbook for automatic containment actions. "
                    "Estimated savings: {:.1f} analyst-hours/period once automated.".format(
                        hours),
                    hours)

            elif total >= 100 and auto_pct >= 0.90:
                self._f(rid,
                    "Auto-Closure Candidate: {} ({:.0%} already auto-closed)".format(
                        rid, auto_pct),
                    "low",
                    "Rule '{}' has {:.0%} of alerts auto-closed — consider converting "
                    "to background enrichment with no analyst queue entry.".format(
                        rid, auto_pct),
                    MITRE["automate"],
                    "If TP rate is acceptable, remove from analyst queue entirely. "
                    "Saves queue clutter for high-value alerts.")

    # ── Summary ──────────────────────────────────────────────────────────────
    def _summary(self, rules, analysts):
        total_alerts = sum(d["alerts"] for d in rules.values())
        total_tp     = sum(d["true_positives"] for d in rules.values())
        total_fp     = sum(d["false_positives"] for d in rules.values())
        actionable   = sum(d["tickets"] for d in rules.values())
        overall_tp   = total_tp / total_alerts if total_alerts else 0
        overall_fp   = total_fp / total_alerts if total_alerts else 0
        top_noise    = sorted(rules.items(),
                              key=lambda x: x[1]["false_positives"], reverse=True)[:3]

        sev = ("critical" if overall_fp > 0.60 else
               "high"     if overall_fp > 0.35 else
               "medium"   if overall_fp > 0.20 else "low")

        self._f("SUMMARY",
            "SOC Alert Health: {:.0%} True Positive Rate | {:.0%} False Positive Rate".format(
                overall_tp, overall_fp),
            sev,
            "Total: {} alerts | {} TP ({:.0%}) | {} FP ({:.0%}) | "
            "{} tickets created | {} analysts. "
            "Top noise sources: {}.".format(
                total_alerts, total_tp, overall_tp,
                total_fp, overall_fp, actionable, analysts,
                ", ".join(r[0] for r in top_noise)),
            MITRE["noise"],
            "Industry benchmark: >50% TP rate. "
            "Immediate focus: {}. "
            "Each 1% FP reduction at current volume saves ~{:.1f} analyst-hours/day.".format(
                ", ".join(r[0] for r in top_noise[:2]),
                total_fp * 0.01 * TRIAGE_MINUTES.get("medium",7) / 60))
