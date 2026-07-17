"""
Active Directory Health Auditor
Audits AD misconfigurations: stale accounts, unconstrained delegation,
DCSync rights, weak password policies, dangerous group nesting,
AS-REP roastable accounts, and AdminSDHolder artifacts.
"""
import logging
logger = logging.getLogger(__name__)

MITRE = {
    "stale":      "T1078.002 - Valid Accounts: Domain Accounts (stale credential)",
    "delegation": "T1558.003 - Steal or Forge Kerberos Tickets (unconstrained delegation)",
    "asrep":      "T1558.004 - AS-REP Roasting",
    "password":   "T1110 - Brute Force (weak policy enables cracking)",
    "nesting":    "T1078.002 - Valid Accounts (excessive group nesting)",
    "admincount": "T1078.002 - Valid Accounts (AdminSDHolder artifact)",
    "dcsync":     "T1003.006 - DCSync (excessive replication rights)",
    "spn":        "T1558.003 - Kerberoasting (SPN on user account)",
}

PRIVILEGED_GROUPS = {
    "Domain Admins","Enterprise Admins","Schema Admins","Administrators",
    "Account Operators","Backup Operators","Print Operators","Server Operators",
}
DCSYNC_RIGHTS = {
    "DS-Replication-Get-Changes",
    "DS-Replication-Get-Changes-All",
    "DS-Replication-Get-Changes-In-Filtered-Set",
}
EOL_OS = {"windows server 2003","windows server 2008","windows xp","windows vista","windows 7"}

class ADHealthAuditor:
    def __init__(self): self.findings = []

    def audit_all(self, data):
        for u in data.get("users",[]): self._audit_user(u)
        for c in data.get("computers",[]): self._audit_computer(c)
        for g in data.get("groups",[]): self._audit_group(g)
        for p in data.get("password_policies",[]): self._audit_policy(p)
        for a in data.get("domain_acls",[]): self._audit_acl(a)
        return self.findings

    def _f(self, obj, title, sev, detail, mitre, rec):
        self.findings.append({"object":obj,"title":title,"severity":sev,
            "detail":detail,"mitre_technique":mitre,"recommendation":rec})

    def _audit_user(self, u):
        name       = u.get("samaccountname","?")
        enabled    = u.get("enabled",True)
        last_logon = u.get("days_since_last_logon",0)
        last_pwd   = u.get("days_since_password_change",0)
        pwd_never  = u.get("password_never_expires",False)
        no_preauth = u.get("no_preauthentication_required",False)
        spns       = u.get("service_principal_names",[])
        admincount = u.get("admincount",0)
        member_of  = u.get("member_of",[])
        is_svc     = any(kw in name.lower() for kw in ("svc","service","_sa","sa_"))

        if enabled and last_logon > 90:
            self._f(name,"Stale Enabled Account: {} ({} days)".format(name,last_logon),
                "high" if last_logon>180 else "medium",
                "Account '{}' inactive {} days but enabled — prime credential stuffing target.".format(
                    name,last_logon),
                MITRE["stale"],"Disable accounts inactive >90 days. Archive at 180 days.")

        if enabled and no_preauth:
            self._f(name,"AS-REP Roastable Account: {}".format(name),"critical",
                "Account '{}' has no Kerberos pre-auth required — any unauthenticated "
                "user can request a crackable AS-REP hash offline.".format(name),
                MITRE["asrep"],"Enable Kerberos pre-authentication immediately. "
                "This should never be disabled without a legacy application requirement.")

        if enabled and spns and not is_svc:
            self._f(name,"Kerberoastable User Account: {}".format(name),"high",
                "Regular user '{}' has SPN(s): {}. Any domain user can request "
                "a crackable TGS ticket.".format(name,", ".join(spns[:2])),
                MITRE["spn"],"Remove SPN from user account or migrate to gMSA.")

        if pwd_never and not is_svc and enabled:
            self._f(name,"Password Never Expires (non-service): {}".format(name),"medium",
                "Account '{}' password never expires — increases cracking window.".format(name),
                MITRE["password"],"Enable expiration. Use 15+ char passphrase to ease rotation.")

        if enabled and last_pwd > 365:
            self._f(name,"Password Unchanged {} Days: {}".format(last_pwd,name),"medium",
                "Account '{}' password is {} days old.".format(name,last_pwd),
                MITRE["password"],"Force password reset. Review account for compromise indicators.")

        if admincount==1 and not any(g in PRIVILEGED_GROUPS for g in member_of):
            self._f(name,"Unexpected AdminCount=1: {}".format(name),"high",
                "Account '{}' has adminCount=1 but is not in any privileged group — "
                "AdminSDHolder artifact, retains protected ACL settings invisibly.".format(name),
                MITRE["admincount"],"Reset adminCount to 0 and re-apply standard ACL inheritance.")

    def _audit_computer(self, c):
        name      = c.get("name","?")
        enabled   = c.get("enabled",True)
        is_dc     = c.get("is_domain_controller",False)
        delegation= c.get("unconstrained_delegation",False)
        last_logon= c.get("days_since_last_logon",0)
        os_ver    = c.get("operating_system","")

        if delegation and not is_dc and enabled:
            self._f(name,"Unconstrained Delegation Enabled: {}".format(name),"critical",
                "Computer '{}' has unconstrained delegation — any service here can "
                "impersonate ANY domain user to ANY service. Combined with printer bug "
                "coercion, this enables full domain compromise.".format(name),
                MITRE["delegation"],"Disable immediately. Replace with resource-based "
                "constrained delegation scoped to specific services.")

        if enabled and last_logon > 90:
            self._f(name,"Stale Computer Account: {} ({} days)".format(name,last_logon),"low",
                "Computer '{}' has not authenticated in {} days.".format(name,last_logon),
                MITRE["stale"],"Verify if machine exists. Disable if decommissioned.")

        if any(eol in os_ver.lower() for eol in EOL_OS):
            self._f(name,"End-of-Life OS: {} ({})".format(name,os_ver),"critical",
                "Computer '{}' runs '{}' — end-of-life, no security patches, "
                "vulnerable to EternalBlue and similar exploits.".format(name,os_ver),
                MITRE["stale"],"Decommission or migrate immediately. Isolate with firewall rules.")

    def _audit_group(self, g):
        name    = g.get("name","?")
        members = g.get("members",[])
        nested  = [m for m in members if m.get("type")=="group"]
        users   = [m for m in members if m.get("type")=="user"]

        if name in PRIVILEGED_GROUPS and nested:
            self._f(name,"Nested Groups in Privileged Group: {}".format(name),"high",
                "Privileged group '{}' contains {} nested group(s): {}. Nesting obscures "
                "effective privilege — nested members inherit all rights invisibly.".format(
                    name,len(nested),", ".join(n.get("name","?") for n in nested[:3])),
                MITRE["nesting"],"Use direct membership only for Tier 0/1 groups. "
                "Audit effective membership quarterly.")

        if name in PRIVILEGED_GROUPS and len(users) > 10:
            self._f(name,"Overpopulated Privileged Group: {} ({} members)".format(
                name,len(users)),"high",
                "Privileged group '{}' has {} direct members — best practice is <5.".format(
                    name,len(users)),
                MITRE["nesting"],"Review all members. Remove unnecessary access. "
                "Use just-in-time privileged access where possible.")

    def _audit_policy(self, p):
        name       = p.get("name","Default Domain Policy")
        min_len    = p.get("min_password_length",0)
        complexity = p.get("complexity_enabled",False)
        lockout    = p.get("lockout_threshold",0)
        history    = p.get("password_history_count",0)

        if min_len < 12:
            self._f(name,"Weak Minimum Password Length: {} chars".format(min_len),"high",
                "Policy '{}' requires only {} characters — cracked in seconds with modern GPUs.".format(
                    name,min_len),
                MITRE["password"],"Increase to 15+ characters. Consider passphrase policy.")

        if not complexity:
            self._f(name,"Password Complexity Disabled","high",
                "Policy '{}' allows passwords like 'password' or '123456'.".format(name),
                MITRE["password"],"Enable complexity. Deploy banned-password list.")

        if lockout == 0:
            self._f(name,"No Account Lockout Configured","critical",
                "Policy '{}' has no lockout threshold — brute force can run indefinitely.".format(name),
                MITRE["password"],"Set lockout to 5–10 attempts with 30-minute duration. "
                "Alert on Event ID 4740.")

        if history < 10:
            self._f(name,"Short Password History: {} remembered".format(history),"medium",
                "Policy '{}' remembers only {} passwords — users can cycle and reuse.".format(
                    name,history),
                MITRE["password"],"Set history to 24 (Microsoft recommendation).")

    def _audit_acl(self, a):
        principal = a.get("principal","?")
        target    = a.get("target","?")
        rights    = a.get("rights",[])
        is_dc     = a.get("principal_is_dc",False)
        target_t  = a.get("target_type","")

        dcsync = set(rights) & DCSYNC_RIGHTS
        if dcsync and not is_dc:
            self._f(principal,"DCSync Rights on Non-DC: {}".format(principal),"critical",
                "Principal '{}' has replication rights on '{}': {}. Enables DCSync — "
                "dumping all domain password hashes without touching a DC.".format(
                    principal,target,", ".join(dcsync)),
                MITRE["dcsync"],"Remove replication rights immediately. Only DCs should hold these. "
                "Audit when and how these rights were granted.")

        if "WriteDACL" in rights and target_t == "domain":
            self._f(principal,"WriteDACL on Domain Root: {}".format(principal),"critical",
                "Principal '{}' has WriteDACL on domain root — can grant themselves "
                "any right including DCSync without needing Domain Admin.".format(principal),
                MITRE["dcsync"],"Remove WriteDACL from domain root immediately.")
