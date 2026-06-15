"""
Credential Stuffing Detector — Authentication Attack Analyzer
=============================================================
Detects credential stuffing, password spraying, and brute-force attacks
against authentication endpoints by analysing login failure patterns,
IP diversity, user agent entropy, and velocity anomalies.

MITRE ATT&CK:
  T1110.003 - Brute Force: Password Spraying
  T1110.004 - Brute Force: Credential Stuffing
  T1078     - Valid Accounts (post-compromise)
  T1133     - External Remote Services

Author: Oladapo Damilola (Wizardskull)
"""

import json
import statistics
import sys
from collections import defaultdict
from datetime import datetime, timezone
from math import log2


# ── Configuration ─────────────────────────────────────────────────────────────
CONFIG = {
    "time_window_seconds": 300,      # 5-min sliding window
    "failure_threshold": 10,         # failures from one IP in window
    "user_diversity_threshold": 5,   # unique users tried from one IP
    "spray_ratio_threshold": 0.85,   # failures/total ratio → spraying
    "success_after_fail_threshold": 3,  # successes after N failures = stuffing hit
    "impossible_speed_ms": 500,      # < 500ms between attempts = automated
    "ua_entropy_threshold": 2.5,     # Shannon entropy threshold for UA diversity
    "geo_mismatch_flag": True,       # flag impossible geo pairs (placeholder)
}


# ── Shannon Entropy ──────────────────────────────────────────────────────────
def shannon_entropy(values: list) -> float:
    """Measures diversity. High entropy = many different user agents = bot rotation."""
    if not values:
        return 0.0
    freq = defaultdict(int)
    for v in values:
        freq[v] += 1
    total = len(values)
    return -sum((c / total) * log2(c / total) for c in freq.values())


# ── Attack Classifiers ────────────────────────────────────────────────────────
def classify_attack(ip_data: dict) -> str:
    """Classify the attack type based on observed patterns."""
    failures = ip_data["failures"]
    successes = ip_data["successes"]
    users = ip_data["unique_users"]
    total = failures + successes

    if total == 0:
        return "NONE"

    failure_ratio = failures / total

    # Credential Stuffing: many users, some successes, high failure ratio
    if users > CONFIG["user_diversity_threshold"] and successes > 0 and failure_ratio > 0.80:
        return "CREDENTIAL_STUFFING"

    # Password Spray: many users, almost all failures, low attempts per user
    if users > CONFIG["user_diversity_threshold"] and failure_ratio > CONFIG["spray_ratio_threshold"]:
        attempts_per_user = total / max(users, 1)
        if attempts_per_user < 5:
            return "PASSWORD_SPRAY"

    # Brute Force: few users, many attempts
    if users <= 3 and failures > CONFIG["failure_threshold"] * 2:
        return "BRUTE_FORCE"

    # Threshold-crossing generic
    if failures >= CONFIG["failure_threshold"]:
        return "EXCESSIVE_FAILURES"

    return "SUSPICIOUS"


def detect_automation(timestamps: list) -> dict:
    """Detect automated tooling via inter-request speed analysis."""
    if len(timestamps) < 3:
        return {"automated": False, "evidence": "insufficient_data"}

    sorted_ts = sorted(timestamps)
    intervals_ms = [(sorted_ts[i + 1] - sorted_ts[i]) * 1000
                    for i in range(len(sorted_ts) - 1)]

    min_interval = min(intervals_ms)
    mean_interval = statistics.mean(intervals_ms)
    cv = statistics.stdev(intervals_ms) / mean_interval if mean_interval > 0 else 0

    automated = (
        min_interval < CONFIG["impossible_speed_ms"] or
        (cv < 0.15 and mean_interval < 2000)  # very regular and fast
    )

    return {
        "automated": automated,
        "min_interval_ms": round(min_interval, 1),
        "mean_interval_ms": round(mean_interval, 1),
        "interval_cv": round(cv, 4),
        "evidence": "sub-500ms requests" if min_interval < 500 else (
            "machine-like regularity" if cv < 0.15 else "normal"
        ),
    }


# ── Log Parser ────────────────────────────────────────────────────────────────
def parse_auth_log(log_path: str) -> dict:
    """
    Parse NDJSON auth logs.
    Expected fields: timestamp, ip, username, status (success/failure),
                     user_agent (optional), endpoint (optional)
    """
    ip_tracker = defaultdict(lambda: {
        "failures": 0,
        "successes": 0,
        "unique_users": set(),
        "timestamps": [],
        "user_agents": [],
        "usernames": [],
        "endpoints": set(),
        "first_seen": None,
        "last_seen": None,
    })

    with open(log_path, "r") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                event = json.loads(line)
                ip = event["ip"]
                username = event["username"].lower()
                status = event["status"].lower()
                ts_raw = event["timestamp"]
                ua = event.get("user_agent", "unknown")
                endpoint = event.get("endpoint", "/login")

                if isinstance(ts_raw, (int, float)):
                    ts = float(ts_raw)
                else:
                    ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00")).timestamp()

                d = ip_tracker[ip]
                if status == "failure":
                    d["failures"] += 1
                elif status == "success":
                    d["successes"] += 1

                d["unique_users"].add(username)
                d["timestamps"].append(ts)
                d["user_agents"].append(ua)
                d["usernames"].append(username)
                d["endpoints"].add(endpoint)

                if d["first_seen"] is None or ts < d["first_seen"]:
                    d["first_seen"] = ts
                if d["last_seen"] is None or ts > d["last_seen"]:
                    d["last_seen"] = ts

            except (json.JSONDecodeError, KeyError, ValueError) as e:
                print(f"[WARN] Line {line_num}: {e}", file=sys.stderr)

    # Convert sets for analysis
    for ip, d in ip_tracker.items():
        d["unique_users"] = len(d["unique_users"])

    return dict(ip_tracker)


# ── Detection Engine ──────────────────────────────────────────────────────────
def run_detection(ip_data: dict) -> list:
    alerts = []

    for ip, data in ip_data.items():
        failures = data["failures"]
        successes = data["successes"]
        total = failures + successes

        if total < 5:
            continue

        attack_type = classify_attack(data)
        if attack_type in ("NONE",):
            continue

        automation = detect_automation(data["timestamps"])
        ua_entropy = shannon_entropy(data["user_agents"])

        duration = (data["last_seen"] - data["first_seen"]) if data["first_seen"] and data["last_seen"] else 0
        rate_per_min = (total / duration * 60) if duration > 0 else 0

        severity = "CRITICAL" if attack_type == "CREDENTIAL_STUFFING" else \
                   "HIGH" if attack_type in ("PASSWORD_SPRAY", "BRUTE_FORCE") else "MEDIUM"

        alert = {
            "alert_type": attack_type,
            "severity": severity,
            "mitre_tactic": "Credential Access / Initial Access",
            "mitre_technique": {
                "CREDENTIAL_STUFFING": "T1110.004",
                "PASSWORD_SPRAY": "T1110.003",
                "BRUTE_FORCE": "T1110.001",
                "EXCESSIVE_FAILURES": "T1110",
                "SUSPICIOUS": "T1110",
            }.get(attack_type, "T1110"),
            "src_ip": ip,
            "total_attempts": total,
            "failures": failures,
            "successes": successes,
            "unique_users_targeted": data["unique_users"],
            "failure_ratio": round(failures / total, 4) if total > 0 else 0,
            "rate_per_minute": round(rate_per_min, 2),
            "automated": automation["automated"],
            "automation_evidence": automation["evidence"],
            "ua_entropy": round(ua_entropy, 4),
            "endpoints_hit": list(data["endpoints"]),
            "duration_seconds": round(duration, 1),
            "detection_timestamp": datetime.now(timezone.utc).isoformat(),
            "recommended_action": _recommend(attack_type, successes),
        }
        alerts.append(alert)

    alerts.sort(key=lambda x: (x["severity"] == "CRITICAL", x["severity"] == "HIGH",
                                x["total_attempts"]), reverse=True)
    return alerts


def _recommend(attack_type: str, successes: int) -> str:
    base = {
        "CREDENTIAL_STUFFING": "Block IP immediately. Audit all successful logins from this IP — force password reset for affected accounts. Check for account takeover indicators.",
        "PASSWORD_SPRAY": "Block IP. Review targeted accounts for MFA enrollment. Alert account owners.",
        "BRUTE_FORCE": "Block IP via WAF rule. Enable account lockout if not already active.",
        "EXCESSIVE_FAILURES": "Investigate IP reputation. Consider temporary rate-limit.",
        "SUSPICIOUS": "Monitor closely. Correlate with threat intel.",
    }.get(attack_type, "Investigate.")

    if successes > 0:
        base += f" ⚠️ {successes} SUCCESSFUL LOGIN(S) DETECTED — immediate account audit required."
    return base


# ── Reporting ─────────────────────────────────────────────────────────────────
def print_report(alerts: list):
    print("\n" + "═" * 70)
    print("  CREDENTIAL STUFFING DETECTOR — THREAT REPORT")
    print("═" * 70)

    if not alerts:
        print("  ✅ No authentication attacks detected.")
        return

    print(f"  🚨 {len(alerts)} attacking IP(s) detected\n")
    for i, a in enumerate(alerts, 1):
        print(f"  [{i}] {a['severity']} — {a['alert_type']} | {a['src_ip']}")
        print(f"      Attempts: {a['total_attempts']} | Failures: {a['failures']} | Successes: {a['successes']}")
        print(f"      Users targeted: {a['unique_users_targeted']} | Rate: {a['rate_per_minute']}/min")
        print(f"      Automated: {a['automated']} ({a['automation_evidence']}) | UA Entropy: {a['ua_entropy']}")
        print(f"      MITRE: {a['mitre_technique']}")
        print(f"      Action: {a['recommended_action'][:100]}...")
        print()
    print("═" * 70)


def save_report(alerts: list, output_path: str):
    with open(output_path, "w") as f:
        json.dump({"total_alerts": len(alerts), "alerts": alerts}, f, indent=2)
    print(f"  📄 Report saved → {output_path}")


# ── Entry Point ───────────────────────────────────────────────────────────────
def main():
    log_path = sys.argv[1] if len(sys.argv) > 1 else "sample_auth.ndjson"
    output_path = sys.argv[2] if len(sys.argv) > 2 else "cred_stuffing_report.json"

    print(f"[*] Loading auth log: {log_path}")
    ip_data = parse_auth_auth_log(log_path)
    print(f"[*] Unique source IPs: {len(ip_data)}")

    alerts = run_detection(ip_data)
    print_report(alerts)
    save_report(alerts, output_path)


def parse_auth_auth_log(log_path):
    return parse_auth_log(log_path)


if __name__ == "__main__":
    main()
