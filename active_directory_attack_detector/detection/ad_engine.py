"""
Active Directory Attack Detector
Detects: Kerberoasting, DCSync, AS-REP Roasting, Golden Ticket,
privilege escalation, password spray, and backdoor account creation.
"""
import logging
from collections import defaultdict
logger = logging.getLogger(__name__)

DCSYNC_GUIDS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
    "89e95b76-444d-4c62-991a-0facbeda640c"
}

MITRE = {
    "kerberoast":    "T1558.003 - Kerberoasting",
    "dcsync":        "T1003.006 - DCSync (Credential Dumping)",
    "asrep_roast":   "T1558.004 - AS-REP Roasting",
    "golden_ticket": "T1558.001 - Golden Ticket",
    "priv_escalate": "T1078.002 + T1098 - Privilege Escalation via Group Membership",
    "ad_spray":      "T1110.003 - AD Password Spraying",
    "backdoor_acct": "T1136.002 - Domain Account Creation (Backdoor)",
}

class ADAttackDetector:
    def __init__(self):
        self.alerts = []

    def run(self, events):
        self._kerberoasting(events)
        self._dcsync(events)
        self._asrep_roasting(events)
        self._golden_ticket(events)
        self._privilege_escalation(events)
        self._password_spray(events)
        self._backdoor_account(events)
        logger.info(f"AD detection complete. {len(self.alerts)} alert(s).")
        return self.alerts

    def _a(self, title, sev, user, ip, mitre, ev):
        self.alerts.append({"title":title,"severity":sev,"user":user,
                             "src_ip":ip,"mitre_technique":mitre,"evidence":ev})

    def _kerberoasting(self, events):
        rc4_requests = defaultdict(list)
        for ev in events:
            if ev.get("event_id")==4769 and ev.get("ticket_encryption")=="0x17":
                rc4_requests[ev.get("src_ip","")].append(ev.get("target_service",""))
        for ip, svcs in rc4_requests.items():
            if len(svcs) >= 3:
                users = [e.get("user") for e in events if e.get("src_ip")==ip and e.get("event_id")==4769]
                self._a("Kerberoasting Attack Detected","critical",
                    users[0] if users else "unknown", ip, MITRE["kerberoast"],
                    {"spns_requested":len(svcs),"services":svcs,
                     "encryption":"RC4 (0x17) — Downgrade for offline cracking"})

    def _dcsync(self, events):
        for ev in events:
            if ev.get("event_id")==4662:
                props = set(ev.get("properties",[]))
                if props & DCSYNC_GUIDS:
                    self._a("DCSync Replication Attack Detected","critical",
                        ev.get("user",""), ev.get("src_ip",""), MITRE["dcsync"],
                        {"object_type":ev.get("object_type"),"access_mask":ev.get("access_mask"),
                         "guids_matched":list(props & DCSYNC_GUIDS),
                         "note":"Non-DC requesting replication rights — credential dump attack"})

    def _asrep_roasting(self, events):
        for ev in events:
            if ev.get("event_id")==4768 and ev.get("pre_auth_type")=="0":
                self._a("AS-REP Roasting — Pre-Auth Disabled Account","high",
                    ev.get("user",""), ev.get("src_ip",""), MITRE["asrep_roast"],
                    {"account":ev.get("user"),"pre_auth_type":"0 (disabled)",
                     "note":"Account hash retrievable without valid credentials"})

    def _golden_ticket(self, events):
        for ev in events:
            lifetime = ev.get("ticket_lifetime_hours",0)
            if ev.get("event_id")==4624 and lifetime and int(lifetime) > 100:
                self._a("Golden Ticket Usage Suspected","critical",
                    ev.get("user",""), ev.get("src_ip",""), MITRE["golden_ticket"],
                    {"ticket_lifetime_hours":lifetime,
                     "note":"Ticket lifetime exceeds Kerberos policy max — forged krbtgt ticket"})

    def _privilege_escalation(self, events):
        for ev in events:
            if ev.get("event_id")==4728 and ev.get("group") in ("Domain Admins","Enterprise Admins","Schema Admins"):
                self._a("User Added to Privileged AD Group","critical",
                    ev.get("user",""), ev.get("src_ip",""), MITRE["priv_escalate"],
                    {"added_user":ev.get("target_user"),"group":ev.get("group"),
                     "added_by":ev.get("user")})

    def _password_spray(self, events):
        ip_users = defaultdict(set)
        for ev in events:
            if ev.get("event_id")==4771 and ev.get("failure_code")=="0x18":
                ip_users[ev.get("src_ip","")].add(ev.get("user",""))
        for ip, users in ip_users.items():
            if len(users) >= 5:
                self._a("AD Kerberos Password Spray Detected","high",
                    "Multiple accounts", ip, MITRE["ad_spray"],
                    {"accounts_targeted":len(users),"sample":list(users)[:5],
                     "note":"Same IP targeting many accounts — classic spray pattern"})

    def _backdoor_account(self, events):
        for ev in events:
            if ev.get("event_id")==4720:
                self._a("New Domain Account Created — Possible Backdoor","high",
                    ev.get("user",""), ev.get("src_ip",""), MITRE["backdoor_acct"],
                    {"new_account":ev.get("new_account"),"created_by":ev.get("user")})
