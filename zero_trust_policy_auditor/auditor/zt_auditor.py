import logging
logger = logging.getLogger(__name__)

MITRE = {
    "no_mfa":    "T1078 - Valid Accounts (no MFA)",
    "no_seg":    "T1021 - Remote Services (flat network)",
    "over_priv": "T1098 - Account Manipulation (excessive permissions)",
    "no_mon":    "T1562.008 - Disable Cloud Logs (no continuous monitoring)",
    "weak_auth": "T1190 - Exploit Public-Facing Application",
    "no_enc":    "T1040 - Network Sniffing (unencrypted)",
    "stale":     "T1078.002 - Domain Account Abuse (stale access)",
    "long_sess": "T1550 - Alternate Authentication (long session)",
}

ZT = {
    "verify":    "Verify Explicitly — Always authenticate and authorise",
    "least":     "Least Privilege — Just-in-time, just-enough access",
    "breach":    "Assume Breach — Minimise blast radius, segment access",
}

class ZeroTrustAuditor:
    def __init__(self): self.findings = []

    def audit(self, config):
        self._network(config.get("network_segments",[]))
        self._users(config.get("users",[]))
        self._apps(config.get("applications",[]))
        self._monitoring(config.get("continuous_monitoring",{}))
        return self.findings

    def _f(self, area, title, sev, detail, mitre, zt, rec):
        self.findings.append({"area":area,"title":title,"severity":sev,
            "detail":detail,"mitre_technique":mitre,"zt_principle":zt,"recommendation":rec})

    def _network(self, segs):
        for s in segs:
            nm = s["segment"]
            if not s.get("micro_segmented"):
                self._f("network","Segment '{}' Not Micro-Segmented".format(nm),"high",
                    "Segment '{}' allows lateral movement between all assets.".format(nm),
                    MITRE["no_seg"],ZT["breach"],
                    "Implement micro-segmentation. Workloads communicate only with permitted peers.")
            if not s.get("east_west_controls"):
                self._f("network","No East-West Traffic Controls in '{}'".format(nm),"high",
                    "No internal traffic inspection in segment '{}'.".format(nm),
                    MITRE["no_seg"],ZT["breach"],
                    "Deploy internal firewalls or service mesh for east-west inspection.")

    def _users(self, users):
        for u in users:
            nm = u["username"]
            if not u.get("mfa_enabled"):
                sev = "critical" if u.get("role") in ("admin","service","third_party") else "high"
                self._f("identity","User '{}' Missing MFA".format(nm),sev,
                    "Zero Trust requires MFA for ALL users. '{}' ({}) has none.".format(nm,u["role"]),
                    MITRE["no_mfa"],ZT["verify"],
                    "Enforce MFA via identity provider. No exceptions.")
            if not u.get("device_trust_verified"):
                self._f("identity","No Device Trust Verification for '{}'".format(nm),"medium",
                    "User '{}' authenticates from unmanaged devices.".format(nm),
                    MITRE["no_mfa"],ZT["verify"],
                    "Enforce device compliance checks via MDM before granting access.")
            if not u.get("least_privilege"):
                self._f("identity","Least Privilege Not Applied for '{}'".format(nm),"high",
                    "User '{}' has broader permissions than role requires.".format(nm),
                    MITRE["over_priv"],ZT["least"],
                    "Remove excess permissions. Implement just-in-time access.")
            timeout = u.get("session_timeout_mins",60)
            if timeout == 0 or timeout > 240:
                self._f("identity","Excessive Session Timeout for '{}' ({} mins)".format(nm,timeout),"medium",
                    "Session timeout {} mins violates continuous verification.".format(timeout),
                    MITRE["long_sess"],ZT["verify"],
                    "Set max session timeout to 60 minutes with re-auth required.")
            reviewed = u.get("access_reviewed_days_ago",0)
            if reviewed > 90:
                self._f("identity","Access Not Reviewed for '{}' ({} days)".format(nm,reviewed),"medium",
                    "Access review overdue by {} days.".format(reviewed-90),
                    MITRE["stale"],ZT["least"],
                    "Complete access review immediately. Recertify or remove permissions.")

    def _apps(self, apps):
        for app in apps:
            nm = app["name"]
            auth = app.get("auth_method","")
            if auth in ("none","basic_auth"):
                sev = "critical" if auth=="none" else "high"
                self._f("application","'{}' Uses Weak Auth ({})".format(nm,auth),sev,
                    "Application '{}' uses {} — Zero Trust requires strong federated auth.".format(nm,auth),
                    MITRE["weak_auth"],ZT["verify"],
                    "Migrate to SSO + MFA via identity provider. Retire basic auth.")
            if not app.get("encrypted_in_transit"):
                self._f("application","'{}' Traffic Not Encrypted in Transit".format(nm),"critical",
                    "Application '{}' transmits data unencrypted.".format(nm),
                    MITRE["no_enc"],ZT["breach"],
                    "Enforce TLS 1.2+ everywhere. No HTTP in production.")
            if not app.get("access_logs"):
                self._f("application","'{}' Has No Access Logging".format(nm),"high",
                    "No access logs for '{}' — cannot audit or detect anomalies.".format(nm),
                    MITRE["no_mon"],ZT["breach"],
                    "Enable comprehensive access logging. Forward to SIEM.")

    def _monitoring(self, mon):
        checks = [
            ("behaviour_analytics_enabled","User Behaviour Analytics Not Enabled","high",
             "Cannot detect insider threats without UEBA."),
            ("privileged_session_recording","Privileged Session Recording Not Enabled","high",
             "Zero Trust requires all privileged sessions recorded for audit."),
            ("log_all_access","Not Logging All Access Events","medium",
             "Zero Trust requires comprehensive access logging."),
            ("anomaly_detection","No Anomaly Detection in Place","medium",
             "Cannot detect baseline deviations without anomaly detection."),
        ]
        for field, title, sev, detail in checks:
            if not mon.get(field):
                self._f("monitoring",title,sev,detail,MITRE["no_mon"],ZT["breach"],
                    "Enable {} as part of Zero Trust continuous verification.".format(field.replace("_"," ")))
