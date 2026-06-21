import re, logging
from collections import defaultdict
logger = logging.getLogger(__name__)

MITRE = {
    "brute":    "T1110.001 - Brute Force: Password Guessing",
    "spray":    "T1110.003 - Brute Force: Password Spraying",
    "stuffing": "T1110.004 - Brute Force: Credential Stuffing",
    "lockout":  "T1110 - Brute Force: Lockout Evasion",
    "rce":      "T1133 - External Remote Services: Post-Auth",
    "distrib":  "T1110 - Brute Force: Distributed Attack",
}

SERVICES = {
    "ssh":  {"port": 22,   "lockout_threshold": 5,  "typical_gap_sec": 0.5},
    "rdp":  {"port": 3389, "lockout_threshold": 5,  "typical_gap_sec": 1.0},
    "ftp":  {"port": 21,   "lockout_threshold": 3,  "typical_gap_sec": 0.3},
    "smtp": {"port": 25,   "lockout_threshold": 10, "typical_gap_sec": 2.0},
    "web":  {"port": 443,  "lockout_threshold": 10, "typical_gap_sec": 0.2},
}

class BruteForceDetector:
    def __init__(self): self.findings = []

    def detect_all(self, data):
        events   = data.get("auth_events", [])
        ip_data  = defaultdict(lambda: {
            "failures": [], "successes": [], "usernames": set(), "timestamps": []
        })
        usr_data = defaultdict(lambda: {"ips": set(), "failures": 0, "successes": 0})

        for ev in events:
            ip   = ev.get("src_ip", "")
            user = ev.get("username", "").lower()
            svc  = ev.get("service", "ssh").lower()
            ts   = ev.get("timestamp_epoch", 0)
            status = ev.get("status", "failure").lower()
            d = ip_data[(ip, svc)]
            u = usr_data[user]
            d["timestamps"].append(ts)
            d["usernames"].add(user)
            u["ips"].add(ip)
            if status == "failure":
                d["failures"].append({"ts": ts, "user": user})
                u["failures"] += 1
            else:
                d["successes"].append({"ts": ts, "user": user})
                u["successes"] += 1

        for (ip, svc), d in ip_data.items():
            self._analyse_ip(ip, svc, d)
        for user, u in usr_data.items():
            self._analyse_user(user, u)

        self.findings.sort(key=lambda f: {"critical":0,"high":1,"medium":2,"low":3}.get(f["severity"],9))
        return self.findings

    def _f(self, src, title, sev, detail, mitre, rec):
        self.findings.append({"source": src, "title": title, "severity": sev,
            "detail": detail, "mitre_technique": mitre, "recommendation": rec})

    def _analyse_ip(self, ip, svc, d):
        fail_count = len(d["failures"])
        succ_count = len(d["successes"])
        unique_users = len(d["usernames"])
        cfg = SERVICES.get(svc, {"lockout_threshold": 5, "typical_gap_sec": 1.0})

        if fail_count < cfg["lockout_threshold"]:
            return

        # Speed: sub-threshold per-user to evade lockout
        lockout_evade = False
        user_fail_counts = defaultdict(int)
        for f in d["failures"]:
            user_fail_counts[f["user"]] += 1
        if all(c < cfg["lockout_threshold"] for c in user_fail_counts.values()) and unique_users > 3:
            lockout_evade = True

        # Attack type classification
        if unique_users > 10 and fail_count > 20:
            attack_type = "CREDENTIAL_STUFFING"
            sev = "critical"
            mitre = MITRE["stuffing"]
        elif unique_users > 5 and succ_count == 0:
            attack_type = "PASSWORD_SPRAY"
            sev = "high"
            mitre = MITRE["spray"]
        elif unique_users <= 3 and fail_count > cfg["lockout_threshold"] * 3:
            attack_type = "BRUTE_FORCE"
            sev = "high"
            mitre = MITRE["brute"]
        else:
            attack_type = "EXCESSIVE_FAILURES"
            sev = "medium"
            mitre = MITRE["brute"]

        # Speed analysis
        ts = sorted(d["timestamps"])
        if len(ts) >= 3:
            intervals = [(ts[i+1]-ts[i]) for i in range(len(ts)-1) if ts[i+1]-ts[i] > 0]
            if intervals:
                min_gap = min(intervals)
                if min_gap < cfg["typical_gap_sec"]:
                    sev = "critical" if sev == "high" else sev

        detail = ("{} on {}: {} failure(s), {} success(es), {} unique user(s). "
                  "Lockout evasion: {}.".format(
                      attack_type, svc.upper(), fail_count, succ_count,
                      unique_users, lockout_evade))

        self._f(ip, "{} Detected on {} from {}".format(attack_type, svc.upper(), ip),
            sev, detail, mitre,
            "Block {} at firewall. Enable geo-restriction on {}. "
            "Enforce MFA. Review successful logins for compromise.".format(ip, svc.upper()))

        # Success after failures = likely compromise
        if succ_count > 0 and fail_count >= cfg["lockout_threshold"]:
            users_hit = list({s["user"] for s in d["successes"]})
            self._f(ip,
                "Successful Login After {} Failures on {} — Possible Compromise".format(
                    fail_count, svc.upper()),
                "critical",
                "IP {} succeeded after {} failures. Users: {}.".format(
                    ip, fail_count, ", ".join(users_hit)),
                MITRE["rce"],
                "IMMEDIATE: Force password reset for {}. Review all sessions. "
                "Check for persistence mechanisms.".format(", ".join(users_hit)))

    def _analyse_user(self, user, u):
        if not user:
            return
        # Distributed attack: same username targeted from many IPs
        if len(u["ips"]) >= 5 and u["failures"] >= 10:
            self._f(user,
                "Distributed Attack Targeting Account: {}".format(user),
                "high",
                "Account '{}' targeted from {} unique IPs with {} failures.".format(
                    user, len(u["ips"]), u["failures"]),
                MITRE["distrib"],
                "Force MFA on account '{}'. Alert account owner. "
                "Consider temporary account lock during investigation.".format(user))
