"""
SOC Metrics Calculator - Computes key SOC performance indicators.
MTTD, MTTR, MTTC, alert volume, true/false positive rates,
SLA compliance, analyst workload distribution.
"""
import logging
from datetime import datetime
from collections import defaultdict

logger = logging.getLogger(__name__)

def _mins(start, end):
    try:
        s = datetime.fromisoformat(str(start))
        e = datetime.fromisoformat(str(end))
        return round((e - s).total_seconds() / 60, 1)
    except Exception:
        return None

def _hours(start, end):
    m = _mins(start, end)
    return round(m / 60, 2) if m is not None else None


class MetricsCalculator:
    def calculate(self, data):
        alerts    = data.get("alerts", [])
        incidents = data.get("incidents", [])
        sla       = data.get("sla_targets", {})
        period    = data.get("period", "")

        # ── Alert volume ──────────────────────────────────────────────────
        total_alerts = len(alerts)
        by_severity  = defaultdict(int)
        for a in alerts:
            by_severity[a["severity"]] += 1

        # ── True / False positive rates ───────────────────────────────────
        tp = sum(1 for a in alerts if a.get("true_positive"))
        fp = total_alerts - tp
        tp_rate = round(tp / total_alerts * 100, 1) if total_alerts else 0
        fp_rate = round(fp / total_alerts * 100, 1) if total_alerts else 0

        # ── MTTA — Mean Time to Acknowledge ──────────────────────────────
        ack_times = [_mins(a["created"], a["acknowledged"])
                     for a in alerts if a.get("acknowledged")]
        mtta = round(sum(ack_times) / len(ack_times), 1) if ack_times else 0

        # ── MTTR — Mean Time to Resolve (alerts) ─────────────────────────
        res_times = [_mins(a["created"], a["resolved"])
                     for a in alerts if a.get("resolved")]
        mttr_alert = round(sum(res_times) / len(res_times), 1) if res_times else 0

        # ── MTTC / MTTI — Mean Time to Contain / Mean Time to Resolve (incidents) ─
        contain_times = [_hours(i["created"], i["contained"])
                         for i in incidents if i.get("contained")]
        resolve_times = [_hours(i["created"], i["resolved"])
                         for i in incidents if i.get("resolved")]
        mttc = round(sum(contain_times) / len(contain_times), 2) if contain_times else 0
        mtti = round(sum(resolve_times) / len(resolve_times), 2) if resolve_times else 0

        # ── SLA Compliance ────────────────────────────────────────────────
        sla_pass = sla_fail = 0
        sla_breaches = []
        for a in alerts:
            sev   = a["severity"]
            limit = sla.get(f"{sev}_acknowledge_mins", 999)
            ack_m = _mins(a["created"], a.get("acknowledged",""))
            if ack_m is None:
                continue
            if ack_m <= limit:
                sla_pass += 1
            else:
                sla_fail += 1
                sla_breaches.append({
                    "alert_id": a["id"], "severity": sev,
                    "target_mins": limit, "actual_mins": ack_m,
                    "overrun_mins": round(ack_m - limit, 1)
                })
        sla_compliance = round(sla_pass / (sla_pass + sla_fail) * 100, 1) if (sla_pass + sla_fail) else 0

        # ── Analyst workload ──────────────────────────────────────────────
        analyst_load = defaultdict(lambda: {"total":0,"tp":0,"fp":0})
        for a in alerts:
            analyst = a.get("analyst","unknown")
            analyst_load[analyst]["total"] += 1
            if a.get("true_positive"):
                analyst_load[analyst]["tp"] += 1
            else:
                analyst_load[analyst]["fp"] += 1

        # ── Severity MTTA breakdown ───────────────────────────────────────
        sev_mtta = {}
        for sev in ["critical","high","medium","low"]:
            sev_times = [_mins(a["created"], a["acknowledged"])
                         for a in alerts
                         if a["severity"] == sev and a.get("acknowledged")]
            if sev_times:
                sev_mtta[sev] = round(sum(sev_times) / len(sev_times), 1)

        return {
            "period":             period,
            "total_alerts":       total_alerts,
            "alerts_by_severity": dict(by_severity),
            "true_positives":     tp,
            "false_positives":    fp,
            "tp_rate_pct":        tp_rate,
            "fp_rate_pct":        fp_rate,
            "mtta_mins":          mtta,
            "mtta_by_severity":   sev_mtta,
            "mttr_alert_mins":    mttr_alert,
            "total_incidents":    len(incidents),
            "mttc_hours":         mttc,
            "mtti_hours":         mtti,
            "sla_compliance_pct": sla_compliance,
            "sla_breaches":       sla_breaches,
            "analyst_workload":   dict(analyst_load),
        }
