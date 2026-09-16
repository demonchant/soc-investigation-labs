import logging
logger = logging.getLogger(__name__)

MITRE = {
    "stale":   "T1110 - Brute Force (stale credentials)",
    "no_mfa":  "T1078 - Valid Accounts (no MFA)",
    "reuse":   "T1110.002 - Password Cracking (reused)",
    "hash":    "T1003 - Credential Dumping (weak hash)",
    "svc":     "T1098.001 - Account Manipulation (stale service)",
    "length":  "T1110.001 - Password Guessing (too short)",
}
HASH_STRENGTH = {
    "$2b$12$":"STRONG","$2b$10$":"ACCEPTABLE",
    "$2b$04$":"WEAK","$1$":"CRITICAL_MD5","$6$":"ACCEPTABLE"
}

class PolicyAnalyser:
    def __init__(self, policy):
        self.policy = policy
        self.findings = []

    def analyse(self, accounts):
        for acc in accounts:
            self._age(acc); self._mfa(acc)
            self._reuse(acc); self._hash(acc)
            self._length(acc); self._service(acc)
        return self.findings

    def _f(self, user, title, sev, detail, mitre, rec):
        self.findings.append({
            "username":user,"title":title,"severity":sev,
            "detail":detail,"mitre_technique":mitre,"recommendation":rec
        })

    def _age(self, acc):
        max_age = self.policy.get("max_age_days", 90)
        age = acc.get("last_changed_days_ago", 0)
        if age > max_age * 2:
            self._f(acc["username"], "Password Not Changed in {} Days".format(age),
                "critical", "Policy requires rotation every {} days.".format(max_age),
                MITRE["stale"], "Force immediate password reset.")
        elif age > max_age:
            self._f(acc["username"], "Password Overdue — {} Days".format(age),
                "high", "Exceeds {}-day rotation policy.".format(max_age),
                MITRE["stale"], "Schedule reset within 48 hours.")

    def _mfa(self, acc):
        if self.policy.get("require_mfa") and not acc.get("mfa_enabled"):
            sev = "critical" if acc.get("account_type") in ("admin","service") else "high"
            self._f(acc["username"], "Account Missing MFA", sev,
                "MFA required by policy but not enabled.",
                MITRE["no_mfa"], "Enable MFA immediately.")

    def _reuse(self, acc):
        if acc.get("password_reused"):
            self._f(acc["username"], "Password Reuse Detected", "high",
                "Using a previously used password.",
                MITRE["reuse"], "Force new unique password.")

    def _hash(self, acc):
        h = acc.get("password_hash","")
        for prefix, strength in HASH_STRENGTH.items():
            if h.startswith(prefix):
                if strength in ("WEAK","CRITICAL_MD5"):
                    sev = "critical" if "CRITICAL" in strength else "high"
                    self._f(acc["username"],
                        "Weak Hash Algorithm ({})".format(prefix.strip("$")), sev,
                        "Hash strength: {}. Fast offline cracking possible.".format(strength),
                        MITRE["hash"], "Rehash with bcrypt rounds>=12 or Argon2id.")
                break

    def _length(self, acc):
        min_len = self.policy.get("min_length", 12)
        est = acc.get("length_estimate", 12)
        if est < min_len:
            sev = "critical" if est < 8 else "high"
            self._f(acc["username"],
                "Password Below Minimum Length ({} < {})".format(est, min_len), sev,
                "Estimated length {} below policy minimum {}.".format(est, min_len),
                MITRE["length"], "Force reset requiring minimum {} chars.".format(min_len))

    def _service(self, acc):
        if acc.get("account_type") == "service":
            max_age = self.policy.get("service_account_rotation_days", 180)
            age = acc.get("last_changed_days_ago", 0)
            if age > max_age:
                self._f(acc["username"],
                    "Service Account Stale — {} Days".format(age), "high",
                    "Not rotated in {} days (policy: {}).".format(age, max_age),
                    MITRE["svc"], "Rotate service credentials immediately.")
