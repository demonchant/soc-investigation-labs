import logging
logger = logging.getLogger(__name__)

MITRE = {
    "exploited": "T1190 - Exploit Public-Facing Application",
    "overdue":   "T1210 - Exploitation of Remote Services",
    "low_pct":   "T1068 - Exploitation for Privilege Escalation",
    "no_scan":   "Configuration hygiene — asset not scanned recently",
}

class ComplianceTracker:
    def __init__(self, sla):
        self.sla = sla
        self.findings = []

    def evaluate(self, assets):
        for a in assets:
            self._exploited(a); self._sla(a)
            self._compliance(a); self._scan(a)
        return self.findings

    def _f(self, aid, host, title, sev, detail, mitre, overrun=0):
        self.findings.append({"asset_id":aid,"hostname":host,"title":title,
            "severity":sev,"detail":detail,"mitre_technique":mitre,"days_overdue":overrun})

    def _exploited(self, a):
        if a.get("known_exploited_missing") and a.get("patches_missing"):
            p = ", ".join(a["patches_missing"][:3])
            sev = "critical" if a["criticality"] in ("critical","high") else "high"
            self._f(a["asset_id"],a["hostname"],"Missing Patch With Known Active Exploitation",sev,
                "{} missing patch(es) including actively exploited: {}".format(len(a["patches_missing"]),p),
                MITRE["exploited"])

    def _sla(self, a):
        days = a.get("days_since_patched",0)
        crit = a.get("criticality","medium")
        inet = a.get("internet_facing",False)
        expl = a.get("known_exploited_missing",False)
        if expl and crit in ("critical","high"):
            limit = self.sla.get("critical_exploited_days",1)
        elif crit == "critical": limit = self.sla.get("critical_days",7)
        elif crit == "high":     limit = self.sla.get("high_days",14)
        elif crit == "medium":   limit = self.sla.get("medium_days",30)
        else:                    limit = self.sla.get("low_days",90)
        if inet: limit = max(1, limit // 2)
        if days > limit:
            overrun = days - limit
            sev = "critical" if overrun > limit else "high"
            self._f(a["asset_id"],a["hostname"],
                "Patch SLA Breached — {} Days Since Last Patch".format(days),sev,
                "SLA: {} days. Actual: {} days. Overrun: +{} days.".format(limit,days,overrun),
                MITRE["overdue"], overrun)

    def _compliance(self, a):
        pct = a.get("patch_compliance_pct",100)
        missing = len(a.get("patches_missing",[]))
        if pct < 80:
            self._f(a["asset_id"],a["hostname"],"Low Patch Compliance — {}%".format(pct),"high",
                "Only {}% patches applied. {} missing.".format(pct,missing),MITRE["low_pct"])
        elif pct < 90:
            self._f(a["asset_id"],a["hostname"],"Patch Compliance Below Target — {}%".format(pct),"medium",
                "{}% compliance below 90% target.".format(pct),MITRE["low_pct"])

    def _scan(self, a):
        from datetime import datetime
        last = a.get("last_scan","")
        if not last:
            self._f(a["asset_id"],a["hostname"],"Asset Never Scanned","high",
                "No scan date recorded.",MITRE["no_scan"])
            return
        try:
            days_ago = (datetime.now() - datetime.fromisoformat(last)).days
            if days_ago > 30:
                self._f(a["asset_id"],a["hostname"],
                    "Patch Scan Overdue — {} Days Ago".format(days_ago),"medium",
                    "Last scanned {} days ago. Monthly scan required.".format(days_ago),MITRE["no_scan"])
        except ValueError: pass
