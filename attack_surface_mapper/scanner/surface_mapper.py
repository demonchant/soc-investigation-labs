"""
External Attack Surface Mapper
Identifies exposed services, expired certs, default credential risks,
shadow IT, and dangling DNS records from external asset inventories.
"""
import re, logging
logger = logging.getLogger(__name__)

MITRE = {
    "exposed":  "T1190 - Exploit Public-Facing Application",
    "default":  "T1078.001 - Default Accounts",
    "shadow":   "T1583.001 - Acquire Infrastructure: Domains",
    "ssl":      "T1557 - Adversary-in-the-Middle (expired cert)",
    "dns":      "T1584.001 - Compromise Infrastructure: Domains",
    "recon":    "T1592 - Gather Victim Host Information",
}

HIGH_RISK_PORTS = {
    21:    ("FTP",          "cleartext credentials"),
    23:    ("Telnet",       "cleartext, legacy protocol"),
    445:   ("SMB",          "ransomware/lateral movement"),
    1433:  ("MSSQL",        "database direct exposure"),
    3306:  ("MySQL",        "database direct exposure"),
    3389:  ("RDP",          "ransomware/brute force target"),
    5432:  ("PostgreSQL",   "database direct exposure"),
    5900:  ("VNC",          "remote desktop, often unauthenticated"),
    6379:  ("Redis",        "unauthenticated by default"),
    7001:  ("WebLogic",     "known RCE vulnerabilities"),
    8080:  ("HTTP-Alt",     "dev server, often misconfigured"),
    9200:  ("Elasticsearch","unauthenticated by default"),
    27017: ("MongoDB",      "unauthenticated by default"),
    50070: ("Hadoop HDFS",  "NameNode admin UI exposed"),
}

DEFAULT_CRED_SERVICES = {
    "jenkins":    "admin/admin",
    "grafana":    "admin/admin",
    "kibana":     "elastic/changeme",
    "rabbitmq":   "guest/guest",
    "sonarqube":  "admin/admin",
    "gitlab":     "root/5iveL!fe",
    "tomcat":     "tomcat/tomcat",
    "phpmyadmin": "root/(empty)",
    "consul":     "(no auth by default)",
    "vault":      "(dev mode: no auth)",
}

CLOUD_CNAME_PATTERNS = [
    re.compile(r"\.s3\.amazonaws\.com$",      re.I),
    re.compile(r"\.azurewebsites\.net$",       re.I),
    re.compile(r"\.azurestaticapps\.net$",     re.I),
    re.compile(r"\.herokuapp\.com$",           re.I),
    re.compile(r"\.github\.io$",               re.I),
    re.compile(r"\.netlify\.app$",             re.I),
    re.compile(r"\.vercel\.app$",              re.I),
]

SHADOW_IT_PATTERNS = [
    re.compile(r"\b(test|dev|staging|uat|old|legacy|deprecated|backup|temp|tmp)\b", re.I),
]

class AttackSurfaceMapper:
    def __init__(self): self.findings = []

    def map_all(self, data):
        for asset in data.get("assets", []):
            self._assess_asset(asset)
        self._detect_dangling_dns(data.get("dns_records", []))
        self._flag_shadow_it(data.get("assets", []))
        return self.findings

    def _f(self, asset, title, sev, detail, mitre, rec):
        self.findings.append({"asset": asset, "title": title, "severity": sev,
            "detail": detail, "mitre_technique": mitre, "recommendation": rec})

    def _assess_asset(self, asset):
        host    = asset.get("hostname", asset.get("ip", "?"))
        ip      = asset.get("ip", "")
        ports   = asset.get("open_ports", [])
        ssl     = asset.get("ssl_cert", {})
        banner  = asset.get("service_banner", "").lower()
        owner   = asset.get("owner", "")

        # High-risk port exposure
        for port in ports:
            p = port if isinstance(port, int) else port.get("port", 0)
            if p in HIGH_RISK_PORTS:
                name, risk = HIGH_RISK_PORTS[p]
                sev = "critical" if p in (3389,445,6379,27017,9200) else "high"
                self._f(host, "Exposed {} (:{}) on Internet-Facing Asset".format(name, p), sev,
                    "{} port {} open on external host '{}' ({}). Risk: {}.".format(
                        name, p, host, ip, risk),
                    MITRE["exposed"],
                    "Restrict port {} to VPN/internal only. "
                    "If legitimately public, ensure fully patched and authenticated.".format(p))

        # SSL certificate analysis
        if ssl:
            days = ssl.get("days_until_expiry", 999)
            cn   = ssl.get("common_name", "?")
            ss   = ssl.get("self_signed", False)

            if days <= 0:
                self._f(host, "Expired SSL Certificate: {} ({} days ago)".format(
                    cn, abs(days)), "critical",
                    "Certificate for '{}' expired {} days ago on host '{}'. "
                    "Users bypass browser warning — enables MITM.".format(cn, abs(days), host),
                    MITRE["ssl"],
                    "Renew immediately. Implement auto-renewal (Let's Encrypt) "
                    "with 30-day advance alerting.")
            elif days <= 14:
                self._f(host, "SSL Expiring in {} Days: {}".format(days, cn), "high",
                    "Certificate for '{}' on host '{}' expires in {} days.".format(
                        cn, host, days),
                    MITRE["ssl"], "Renew within 48 hours. Add to cert inventory.")
            elif days <= 30:
                self._f(host, "SSL Expiring in {} Days: {}".format(days, cn), "medium",
                    "Certificate '{}' expires in {} days — schedule renewal.".format(cn, days),
                    MITRE["ssl"], "Renew this week to avoid outage.")

            if ss:
                self._f(host, "Self-Signed Certificate on {}".format(host), "high",
                    "Host '{}' uses self-signed cert — no CA trust. Users who accept "
                    "are vulnerable to MITM via lookalike self-signed cert.".format(host),
                    MITRE["ssl"],
                    "Replace with CA-signed certificate (Let's Encrypt for public services).")

        # Default credential risk
        for svc, creds in DEFAULT_CRED_SERVICES.items():
            if svc in banner:
                self._f(host, "Default Credentials Risk: {} on {}".format(svc.title(), host),
                    "critical",
                    "Banner on '{}' matches '{}' — default credentials: {}. "
                    "If not changed, trivial authentication bypass.".format(host, svc, creds),
                    MITRE["default"],
                    "Verify default credentials are changed. "
                    "Add credential verification to deployment checklist.")

        # Unconfigured web server
        if any(kw in banner for kw in
               ["apache2 default","nginx welcome","iis windows","it works"]):
            self._f(host, "Default Web Server Page Exposed: {}".format(host), "medium",
                "Default web server page on '{}' reveals software/version "
                "and indicates unconfigured or forgotten asset.".format(host),
                MITRE["recon"],
                "Replace default page. If unused, decommission and remove DNS/firewall rules.")

        # No owner
        if not owner or owner.lower() in ("unknown","none",""):
            self._f(host, "Unowned External Asset: {}".format(host), "high",
                "External asset '{}' has no recorded owner — "
                "shadow IT risk, no one responsible for patching.".format(host),
                MITRE["shadow"],
                "Assign owner immediately. Add to CMDB and patch management program.")

    def _detect_dangling_dns(self, dns_records):
        for rec in dns_records:
            rtype  = rec.get("type","").upper()
            name   = rec.get("name","")
            target = rec.get("value","")

            if rtype == "CNAME" and target and rec.get("target_resolves") is False:
                for pattern in CLOUD_CNAME_PATTERNS:
                    if pattern.search(target):
                        self._f(name,
                            "Dangling DNS — Subdomain Takeover Risk: {}".format(name),
                            "critical",
                            "CNAME '{}' → '{}' which NO LONGER EXISTS. "
                            "Attacker can register this cloud resource and serve "
                            "malicious content from your domain.".format(name, target),
                            MITRE["dns"],
                            "URGENT: Remove DNS record or reclaim the cloud resource. "
                            "Subdomain takeovers enable cookie theft and phishing "
                            "from your own domain.")
                        break

            if rtype == "A" and target and not any(
                target.startswith(r) for r in ("10.","172.","192.168.")):
                if rec.get("in_asset_inventory") is False:
                    self._f(name,
                        "DNS A Record Points to Untracked IP: {}".format(target),
                        "medium",
                        "DNS record '{}' → '{}' but IP not in asset inventory — "
                        "possible shadow IT, decommissioned server, or acquired IP.".format(
                            name, target),
                        MITRE["shadow"],
                        "Verify ownership of {}. Add to inventory or remove DNS record.".format(
                            target))

    def _flag_shadow_it(self, assets):
        for asset in assets:
            host         = asset.get("hostname","")
            last_scanned = asset.get("last_scanned_days_ago", 0)
            owner        = asset.get("owner","")
            for pat in SHADOW_IT_PATTERNS:
                if pat.search(host):
                    if last_scanned > 90 or not owner:
                        self._f(host,
                            "Potential Forgotten Asset: {}".format(host), "high",
                            "Hostname '{}' matches shadow IT pattern. "
                            "Last scanned: {} days ago. Owner: '{}'.".format(
                                host, last_scanned, owner or "unassigned"),
                            MITRE["shadow"],
                            "Verify if still needed. Decommission if not. "
                            "Forgotten assets are often unpatched entry points.")
                    break
