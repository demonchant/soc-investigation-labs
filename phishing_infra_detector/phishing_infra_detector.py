"""
Phishing Infrastructure Detector — Lookalike Domain & Mail Threat Analyzer
===========================================================================
Detects phishing infrastructure by analyzing:
  - Lookalike/homoglyph domains targeting your organization
  - Newly registered domains with suspicious characteristics
  - Missing or misconfigured SPF/DKIM/DMARC (email spoofing enablers)
  - MX record anomalies and suspicious mail routing
  - Brand impersonation patterns in domain names

MITRE ATT&CK:
  T1566     - Phishing
  T1566.002 - Spearphishing Link
  T1566.001 - Spearphishing Attachment
  T1584.001 - Compromise Infrastructure: Domains
  T1583.001 - Acquire Infrastructure: Domains

Author: Oladapo Damilola (Wizardskull)
"""

import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone


CONFIG = {
    "protected_brands": [               # your org + common impersonation targets
        "company", "microsoft", "google", "amazon", "paypal",
        "apple", "netflix", "chase", "bankofamerica", "wellsfargo",
        "linkedin", "facebook", "instagram", "binance", "coinbase",
    ],
    "protected_domains": [              # your org's actual domains
        "company.com", "company.org",
    ],
    "new_domain_age_threshold_days": 30,  # domains < 30 days old = suspicious
    "lookalike_edit_distance": 2,
    "suspicious_tlds": {                # TLDs commonly used for phishing
        ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq",
        ".top", ".click", ".link", ".live", ".online",
        ".site", ".pw", ".cc", ".su",
    },
    "dkim_required": True,
    "dmarc_required": True,
}

# Homoglyph character substitutions (visual lookalike chars)
HOMOGLYPHS = {
    "a": ["а", "ä", "â", "á", "à", "ã", "@"],
    "e": ["е", "ë", "é", "è", "ê", "3"],
    "i": ["і", "ï", "í", "ì", "l", "1", "!"],
    "o": ["о", "ö", "ó", "ò", "ô", "0"],
    "u": ["ü", "ú", "ù", "û"],
    "n": ["и", "η"],
    "c": ["с", "ç"],
    "p": ["р"],
    "x": ["х"],
    "y": ["у"],
}

# Common phishing tricks
SUSPICIOUS_BRAND_PATTERNS = [
    r"microsoft[-_]?365", r"office[-_]?365",
    r"paypal[-_]?(secure|login|account|verify)",
    r"amazon[-_]?(prime|aws|payment)",
    r"apple[-_]?(id|icloud|support)",
    r"google[-_]?(drive|docs|account|login)",
    r"coinbase[-_]?(wallet|login|verify)",
    r"binance[-_]?(kyc|account|verify)",
    r"dhl|fedex|ups.*tracking",
    r"irs|hmrc|tax.*refund",
]


def levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if not s2:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for c1 in s1:
        curr = [prev[0] + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j+1]+1, curr[j]+1, prev[j]+(c1 != c2)))
        prev = curr
    return prev[-1]


def has_homoglyph(domain: str, brand: str) -> bool:
    """Check if domain contains homoglyph substitutions of brand name."""
    domain_lower = domain.lower()
    for char, substitutes in HOMOGLYPHS.items():
        for sub in substitutes:
            if sub in domain_lower:
                candidate = domain_lower.replace(sub, char)
                if brand in candidate:
                    return True
    return False


def is_lookalike(domain: str, protected_domains: list, brands: list) -> dict:
    """Comprehensive lookalike detection."""
    domain_base = domain.lower().replace("www.", "")
    # Extract domain without TLD
    parts = domain_base.split(".")
    domain_name = ".".join(parts[:-1]) if len(parts) > 1 else domain_base

    # 1. Direct brand name in suspicious context
    for brand in brands:
        # Brand in subdomain or prefix position (not legit domain itself)
        if brand in domain_name and domain_base not in CONFIG["protected_domains"]:
            return {"lookalike": True, "type": "brand_in_domain", "target": brand}

    # 2. Edit distance to protected domains
    for protected in protected_domains:
        protected_name = protected.split(".")[0]
        dist = levenshtein(domain_name, protected_name)
        if 0 < dist <= CONFIG["lookalike_edit_distance"]:
            return {
                "lookalike": True,
                "type": "edit_distance",
                "target": protected,
                "distance": dist,
            }

    # 3. Homoglyph check
    for brand in brands:
        if has_homoglyph(domain_name, brand):
            return {"lookalike": True, "type": "homoglyph", "target": brand}

    # 4. Suspicious brand patterns
    for pattern in SUSPICIOUS_BRAND_PATTERNS:
        if re.search(pattern, domain_name, re.IGNORECASE):
            return {"lookalike": True, "type": "brand_pattern", "pattern": pattern}

    return {"lookalike": False}


def check_email_security(domain_record: dict) -> list:
    """Check SPF, DKIM, DMARC configuration for email spoofing enablement."""
    issues = []
    spf = domain_record.get("spf_record", "")
    dkim = domain_record.get("dkim_record", "")
    dmarc = domain_record.get("dmarc_record", "")

    if not spf:
        issues.append("MISSING SPF record — domain can be spoofed")
    elif "+all" in spf or "?all" in spf:
        issues.append(f"WEAK SPF policy: '{spf[-10:]}' — allows any sender")

    if not dkim and CONFIG["dkim_required"]:
        issues.append("MISSING DKIM — no email signing")

    if not dmarc and CONFIG["dmarc_required"]:
        issues.append("MISSING DMARC — no enforcement policy")
    elif dmarc:
        if "p=none" in dmarc.lower():
            issues.append("DMARC policy=none — monitor only, no rejection")
        elif "p=quarantine" in dmarc.lower():
            issues.append("DMARC policy=quarantine — partial protection")

    return issues


def parse_domain_log(log_path: str) -> list:
    """
    Parse domain intelligence / DNS passive log (NDJSON).
    Expected: domain, first_seen_days_ago, registrar, hosting_ip,
              spf_record, dkim_record, dmarc_record, mx_records,
              ssl_cert_org (optional), category (optional)
    """
    domains = []
    with open(log_path) as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                domains.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"[WARN] Line {line_num}: {e}", file=sys.stderr)
    return domains


def run_detection(domains: list) -> list:
    alerts = []

    for domain_rec in domains:
        domain = domain_rec.get("domain", "")
        if not domain:
            continue

        indicators = []
        severity = "LOW"
        score = 0

        # 1. Lookalike check
        lookalike = is_lookalike(domain, CONFIG["protected_domains"],
                                  CONFIG["protected_brands"])
        if lookalike["lookalike"]:
            indicators.append(f"lookalike domain ({lookalike['type']}): targets '{lookalike.get('target', lookalike.get('pattern', ''))}'")
            score += 40
            severity = "HIGH"

        # 2. New domain
        age_days = domain_rec.get("first_seen_days_ago", 999)
        if age_days <= CONFIG["new_domain_age_threshold_days"]:
            indicators.append(f"new domain: registered {age_days} days ago")
            score += 20
            if severity == "LOW":
                severity = "MEDIUM"

        # 3. Suspicious TLD
        tld = "." + domain.split(".")[-1].lower()
        if tld in CONFIG["suspicious_tlds"]:
            indicators.append(f"suspicious TLD: {tld}")
            score += 15

        # 4. Email security issues (if this is a sending domain)
        if domain_rec.get("has_mx", False):
            email_issues = check_email_security(domain_rec)
            if email_issues:
                indicators.extend(email_issues)
                score += len(email_issues) * 10
                if len(email_issues) >= 2 and severity != "CRITICAL":
                    severity = "HIGH" if severity != "CRITICAL" else severity

        # 5. Hosting on bulletproof/anonymous infrastructure
        hosting_ip = domain_rec.get("hosting_ip", "")
        if hosting_ip and any(hosting_ip.startswith(r) for r in ["185.220.", "91.108.", "198.98."]):
            indicators.append(f"hosted on known bulletproof/anonymous infrastructure: {hosting_ip}")
            score += 25
            severity = "CRITICAL" if score >= 60 else "HIGH"

        # 6. No SSL / self-signed SSL
        ssl_org = domain_rec.get("ssl_cert_org", "")
        if domain_rec.get("has_ssl") is False:
            indicators.append("no SSL certificate — possible credential phishing page")
            score += 10

        if score < 20:
            continue

        if score >= 70:
            severity = "CRITICAL"
        elif score >= 45 and severity == "MEDIUM":
            severity = "HIGH"

        alerts.append({
            "alert_type": "PHISHING_INFRASTRUCTURE",
            "severity": severity,
            "mitre_technique": "T1566 / T1583.001 / T1584.001",
            "mitre_tactic": "Initial Access / Resource Development",
            "domain": domain,
            "threat_score": min(score, 100),
            "domain_age_days": age_days,
            "indicators": indicators,
            "hosting_ip": domain_rec.get("hosting_ip", ""),
            "registrar": domain_rec.get("registrar", ""),
            "detection_timestamp": datetime.now(timezone.utc).isoformat(),
            "recommended_action": (
                f"Block domain '{domain}' at DNS/proxy level immediately. "
                "Submit to Google SafeBrowsing and PhishTank. "
                "Alert users who may have received emails from this domain. "
                "Contact domain registrar for takedown if impersonating your brand. "
                "Monitor for associated IPs and certificate fingerprints."
            ),
        })

    alerts.sort(key=lambda x: x["threat_score"], reverse=True)
    return alerts


def print_report(alerts: list):
    print("\n" + "═" * 70)
    print("  PHISHING INFRASTRUCTURE DETECTOR — THREAT REPORT")
    print("═" * 70)
    if not alerts:
        print("  ✅ No phishing infrastructure detected.")
        return
    print(f"  🚨 {len(alerts)} suspicious domain(s)\n")
    for i, a in enumerate(alerts, 1):
        print(f"  [{i}] {a['severity']} — Score: {a['threat_score']}/100 | {a['domain']}")
        print(f"      Age: {a['domain_age_days']} days | IP: {a.get('hosting_ip','N/A')}")
        for ind in a["indicators"]:
            print(f"      ⚠ {ind}")
        print(f"      MITRE: {a['mitre_technique']}")
        print()
    print("═" * 70)


def save_report(alerts, path):
    with open(path, "w") as f:
        json.dump({"total_alerts": len(alerts), "alerts": alerts}, f, indent=2)
    print(f"  📄 Report saved → {path}")


def main():
    log_path = sys.argv[1] if len(sys.argv) > 1 else "sample_domains.ndjson"
    out_path = sys.argv[2] if len(sys.argv) > 2 else "phishing_report.json"
    print(f"[*] Loading domain intelligence: {log_path}")
    domains = parse_domain_log(log_path)
    print(f"[*] Domains analyzed: {len(domains)}")
    alerts = run_detection(domains)
    print_report(alerts)
    save_report(alerts, out_path)


if __name__ == "__main__":
    main()
