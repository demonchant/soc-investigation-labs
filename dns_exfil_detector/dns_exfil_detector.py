"""
DNS Exfiltration Detector — Data Theft via DNS Tunnel Analysis
==============================================================
Detects data exfiltration through DNS tunneling by analysing:
  - Subdomain length and entropy (encoded payloads are high-entropy)
  - Query volume and frequency per domain family
  - NXDOMAIN ratios (tunneling tools probe non-existent subdomains)
  - Unique subdomain count per apex domain
  - TXT/NULL record abuse

MITRE ATT&CK:
  T1048.001 - Exfiltration Over Alternative Protocol: DNS
  T1071.004 - Application Layer Protocol: DNS
  T1132.001 - Data Encoding: Standard Encoding (base32/base64 in DNS)

Author: Oladapo Damilola (Wizardskull)
"""

import json
import math
import re
import statistics
import string
import sys
from collections import defaultdict
from datetime import datetime, timezone


# ── Configuration ─────────────────────────────────────────────────────────────
CONFIG = {
    "min_queries_for_analysis": 10,
    "subdomain_entropy_threshold": 3.5,  # Shannon entropy bits; base32 ≈ 4.0+
    "subdomain_length_threshold": 40,    # chars; legit domains rarely exceed 30
    "nxdomain_ratio_threshold": 0.60,    # >60% NXDOMAIN = likely tunneling
    "unique_subdomain_threshold": 20,    # many unique subs per apex = data channel
    "query_rate_per_min_threshold": 30,  # high query rate
    "suspicious_record_types": {"TXT", "NULL", "CNAME"},
    "known_good_apex": {                 # well-known CDN/update domains
        "akadns.net", "awsdns-01.com", "azure-dns.com",
        "cloudflare.com", "fastly.net", "akamaiedge.net",
        "windowsupdate.com", "apple.com", "googleapis.com",
    },
}

# ── Utility ───────────────────────────────────────────────────────────────────
VALID_CHARS = set(string.ascii_lowercase + string.digits + "-")


def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string — high entropy = encoded data."""
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length)
                for count in freq.values())


def extract_apex_domain(fqdn: str) -> str:
    """Extract apex domain (e.g., evil.com from data.evil.com)."""
    fqdn = fqdn.rstrip(".")
    parts = fqdn.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return fqdn


def extract_subdomain(fqdn: str) -> str:
    """Extract subdomain portion."""
    fqdn = fqdn.rstrip(".")
    parts = fqdn.split(".")
    if len(parts) > 2:
        return ".".join(parts[:-2])
    return ""


def looks_like_encoded(subdomain: str) -> dict:
    """Detect base32/base64/hex encoding patterns in subdomain."""
    sub = subdomain.replace(".", "").lower()

    # Base32: A-Z2-7 only
    base32_chars = set("abcdefghijklmnopqrstuvwxyz234567")
    base32_ratio = sum(1 for c in sub if c in base32_chars) / max(len(sub), 1)

    # Hex pattern
    hex_chars = set("0123456789abcdef")
    hex_ratio = sum(1 for c in sub if c in hex_chars) / max(len(sub), 1)

    # Long numeric strings (encoded)
    has_long_numeric = bool(re.search(r'\d{10,}', sub))

    return {
        "base32_ratio": round(base32_ratio, 3),
        "hex_ratio": round(hex_ratio, 3),
        "likely_base32": base32_ratio > 0.90 and len(sub) > 20,
        "likely_hex": hex_ratio > 0.95 and len(sub) > 20,
        "has_long_numeric": has_long_numeric,
    }


# ── Log Parser ────────────────────────────────────────────────────────────────
def parse_dns_log(log_path: str) -> dict:
    """
    Parse DNS query logs (NDJSON).
    Expected fields: timestamp, src_ip, query (FQDN), qtype, rcode (optional)
    """
    apex_tracker = defaultdict(lambda: {
        "queries": 0,
        "nxdomain": 0,
        "unique_subdomains": set(),
        "subdomains_raw": [],
        "timestamps": [],
        "src_ips": set(),
        "qtypes": defaultdict(int),
        "suspicious_qtypes": 0,
    })

    with open(log_path, "r") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                event = json.loads(line)
                fqdn = event["query"].lower().rstrip(".")
                src_ip = event.get("src_ip", "unknown")
                qtype = event.get("qtype", "A").upper()
                rcode = event.get("rcode", "NOERROR").upper()
                ts_raw = event["timestamp"]

                if isinstance(ts_raw, (int, float)):
                    ts = float(ts_raw)
                else:
                    ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00")).timestamp()

                apex = extract_apex_domain(fqdn)
                subdomain = extract_subdomain(fqdn)

                d = apex_tracker[apex]
                d["queries"] += 1
                d["timestamps"].append(ts)
                d["src_ips"].add(src_ip)
                d["qtypes"][qtype] += 1

                if rcode == "NXDOMAIN":
                    d["nxdomain"] += 1

                if subdomain:
                    d["unique_subdomains"].add(subdomain)
                    d["subdomains_raw"].append(subdomain)

                if qtype in CONFIG["suspicious_record_types"]:
                    d["suspicious_qtypes"] += 1

            except (json.JSONDecodeError, KeyError, ValueError) as e:
                print(f"[WARN] Line {line_num}: {e}", file=sys.stderr)

    # Convert sets
    for apex, d in apex_tracker.items():
        d["unique_subdomain_count"] = len(d["unique_subdomains"])
        d["src_ip_count"] = len(d["src_ips"])
        d["src_ips"] = list(d["src_ips"])
        d["unique_subdomains"] = list(d["unique_subdomains"])

    return dict(apex_tracker)


# ── Scoring Engine ────────────────────────────────────────────────────────────
def dns_exfil_score(apex: str, data: dict) -> dict:
    queries = data["queries"]
    if queries < CONFIG["min_queries_for_analysis"]:
        return {"score": 0, "reason": "insufficient_data"}

    if apex in CONFIG["known_good_apex"]:
        return {"score": 0, "reason": "allowlisted"}

    score = 0
    evidence = {}

    # 1. Subdomain entropy analysis (most reliable signal)
    entropies = [shannon_entropy(s) for s in data["subdomains_raw"] if s]
    if entropies:
        avg_entropy = statistics.mean(entropies)
        max_entropy = max(entropies)
        evidence["avg_subdomain_entropy"] = round(avg_entropy, 4)
        evidence["max_subdomain_entropy"] = round(max_entropy, 4)
        if avg_entropy >= CONFIG["subdomain_entropy_threshold"]:
            score += 35
        elif avg_entropy >= 3.0:
            score += 20

    # 2. Subdomain length
    lengths = [len(s) for s in data["subdomains_raw"] if s]
    if lengths:
        avg_length = statistics.mean(lengths)
        evidence["avg_subdomain_length"] = round(avg_length, 2)
        if avg_length >= CONFIG["subdomain_length_threshold"]:
            score += 20
        elif avg_length >= 25:
            score += 10

    # 3. NXDOMAIN ratio
    nxdomain_ratio = data["nxdomain"] / queries
    evidence["nxdomain_ratio"] = round(nxdomain_ratio, 4)
    if nxdomain_ratio >= CONFIG["nxdomain_ratio_threshold"]:
        score += 20
    elif nxdomain_ratio >= 0.30:
        score += 10

    # 4. Unique subdomain volume
    unique_count = data["unique_subdomain_count"]
    evidence["unique_subdomain_count"] = unique_count
    if unique_count >= CONFIG["unique_subdomain_threshold"]:
        score += 15

    # 5. Query rate
    ts = data["timestamps"]
    if len(ts) >= 2:
        duration = max(ts) - min(ts)
        rate = (queries / duration * 60) if duration > 0 else 0
        evidence["queries_per_minute"] = round(rate, 2)
        if rate >= CONFIG["query_rate_per_min_threshold"]:
            score += 10

    # 6. Suspicious record types
    if data["suspicious_qtypes"] > 5:
        score += 10
        evidence["suspicious_record_types_count"] = data["suspicious_qtypes"]

    # 7. Encoding detection on sample subdomains
    sample = data["subdomains_raw"][:10]
    encoded_signals = [looks_like_encoded(s) for s in sample]
    base32_count = sum(1 for e in encoded_signals if e["likely_base32"])
    if base32_count >= 3:
        score += 15
        evidence["base32_encoded_subdomains"] = base32_count

    return {"score": min(score, 100), "evidence": evidence}


# ── Detection Engine ──────────────────────────────────────────────────────────
def run_detection(apex_data: dict) -> list:
    alerts = []
    for apex, data in apex_data.items():
        result = dns_exfil_score(apex, data)
        if result.get("score", 0) >= 50:
            severity = "CRITICAL" if result["score"] >= 80 else \
                       "HIGH" if result["score"] >= 65 else "MEDIUM"
            alerts.append({
                "alert_type": "DNS_EXFILTRATION",
                "severity": severity,
                "mitre_tactic": "Exfiltration / Command and Control",
                "mitre_technique": "T1048.001 / T1071.004 / T1132.001",
                "apex_domain": apex,
                "exfil_score": result["score"],
                "total_queries": data["queries"],
                "src_ips": data["src_ips"],
                "evidence": result.get("evidence", {}),
                "detection_timestamp": datetime.now(timezone.utc).isoformat(),
                "recommended_action": (
                    f"Block domain {apex} at DNS resolver level. "
                    "Capture DNS traffic for forensic analysis. "
                    "Identify process making queries via EDR. "
                    "Check for data classification breach."
                ),
            })
    alerts.sort(key=lambda x: x["exfil_score"], reverse=True)
    return alerts


# ── Reporting ─────────────────────────────────────────────────────────────────
def print_report(alerts: list):
    print("\n" + "═" * 70)
    print("  DNS EXFILTRATION DETECTOR — THREAT REPORT")
    print("═" * 70)
    if not alerts:
        print("  ✅ No DNS exfiltration detected.")
        return
    print(f"  🚨 {len(alerts)} suspicious domain(s)\n")
    for i, a in enumerate(alerts, 1):
        ev = a["evidence"]
        print(f"  [{i}] {a['severity']} — Score: {a['exfil_score']}/100 | {a['apex_domain']}")
        print(f"      Total queries: {a['total_queries']} | IPs: {', '.join(a['src_ips'][:3])}")
        if "avg_subdomain_entropy" in ev:
            print(f"      Avg entropy: {ev['avg_subdomain_entropy']} | Avg length: {ev.get('avg_subdomain_length', 'N/A')}")
        if "nxdomain_ratio" in ev:
            print(f"      NXDOMAIN ratio: {ev['nxdomain_ratio']:.0%} | QPM: {ev.get('queries_per_minute', 'N/A')}")
        print(f"      MITRE: {a['mitre_technique']}")
        print()
    print("═" * 70)


def save_report(alerts: list, output_path: str):
    with open(output_path, "w") as f:
        json.dump({"total_alerts": len(alerts), "alerts": alerts}, f, indent=2)
    print(f"  📄 Report saved → {output_path}")


def main():
    log_path = sys.argv[1] if len(sys.argv) > 1 else "sample_dns.ndjson"
    output_path = sys.argv[2] if len(sys.argv) > 2 else "dns_exfil_report.json"
    print(f"[*] Loading DNS log: {log_path}")
    apex_data = parse_dns_log(log_path)
    print(f"[*] Unique apex domains: {len(apex_data)}")
    alerts = run_detection(apex_data)
    print_report(alerts)
    save_report(alerts, output_path)


if __name__ == "__main__":
    main()
