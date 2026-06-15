"""
Kerberoasting Detector — SPN Ticket Harvesting & Cracking Attempt Analyzer
===========================================================================
Detects Kerberoasting attacks: adversaries request Kerberos TGS tickets
for service accounts (SPNs) and crack them offline. Detects the harvesting
phase via Windows Event ID 4769 analysis — before cracking even begins.

Detection signals:
  - High volume of RC4 (etype 0x17) TGS requests (RC4 = weaker, crackable)
  - One user requesting tickets for many different SPNs rapidly
  - Service ticket requests outside business hours
  - Requests from non-service accounts for service SPNs
  - Mimikatz/Rubeus default request patterns (ticket size, frequency)

MITRE ATT&CK:
  T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting
  T1078.002 - Valid Accounts: Domain Accounts
  T1550.003 - Use Alternate Authentication Material: Pass the Ticket

Author: Oladapo Damilola (Wizardskull)
"""

import json
import statistics
import sys
from collections import defaultdict
from datetime import datetime, timezone


CONFIG = {
    "time_window_seconds": 300,          # 5-min sliding window
    "spn_request_threshold": 5,          # >5 unique SPNs from one user = suspicious
    "rc4_ratio_threshold": 0.80,         # >80% RC4 requests = kerberoasting tool
    "request_speed_threshold_ms": 2000,  # <2s between requests = automated
    "off_hours": (22, 6),                # 10 PM – 6 AM
    "known_service_accounts": {          # legit accounts that request many tickets
        "svc_backup", "svc_monitor", "svc_deploy",
    },
    # RC4 encryption type = 0x17 (23) — weak, offline-crackable
    # AES256 = 0x12 (18) — strong
    "rc4_etype": 23,
    "aes_etypes": {17, 18},
}


def is_off_hours(ts: float) -> bool:
    hour = datetime.fromtimestamp(ts, tz=timezone.utc).hour
    start, end = CONFIG["off_hours"]
    return hour >= start or hour < end


def parse_event_log(log_path: str) -> dict:
    """
    Parse Windows Security Event 4769 logs (Kerberos TGS requests).
    Expected fields: timestamp, event_id, username, service_name,
                     encryption_type (int), ticket_options, src_ip
    """
    user_tracker = defaultdict(lambda: {
        "requests": [],
        "spns": set(),
        "rc4_count": 0,
        "aes_count": 0,
        "src_ips": set(),
        "off_hours_count": 0,
    })

    with open(log_path) as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                ev = json.loads(line)
                if ev.get("event_id") != 4769:
                    continue

                ts_raw = ev["timestamp"]
                ts = float(ts_raw) if isinstance(ts_raw, (int, float)) else \
                    datetime.fromisoformat(ts_raw.replace("Z", "+00:00")).timestamp()

                username = ev.get("username", "").lower().split("@")[0]
                spn = ev.get("service_name", "")
                etype = int(ev.get("encryption_type", 23))
                src_ip = ev.get("src_ip", "")

                d = user_tracker[username]
                d["requests"].append({"ts": ts, "spn": spn, "etype": etype})
                d["spns"].add(spn)
                d["src_ips"].add(src_ip)

                if etype == CONFIG["rc4_etype"]:
                    d["rc4_count"] += 1
                elif etype in CONFIG["aes_etypes"]:
                    d["aes_count"] += 1

                if is_off_hours(ts):
                    d["off_hours_count"] += 1

            except (json.JSONDecodeError, KeyError, ValueError) as e:
                print(f"[WARN] Line {line_num}: {e}", file=sys.stderr)

    for u, d in user_tracker.items():
        d["spns"] = list(d["spns"])
        d["src_ips"] = list(d["src_ips"])
        d["unique_spn_count"] = len(d["spns"])
        total = d["rc4_count"] + d["aes_count"]
        d["rc4_ratio"] = d["rc4_count"] / total if total > 0 else 0
        d["total_requests"] = len(d["requests"])

    return dict(user_tracker)


def detect_automation(requests: list) -> dict:
    if len(requests) < 3:
        return {"automated": False}
    sorted_ts = sorted(r["ts"] for r in requests)
    intervals_ms = [(sorted_ts[i+1] - sorted_ts[i]) * 1000
                    for i in range(len(sorted_ts)-1)]
    min_ms = min(intervals_ms)
    return {
        "automated": min_ms < CONFIG["request_speed_threshold_ms"],
        "min_interval_ms": round(min_ms, 1),
    }


def score_kerberoasting(username: str, data: dict) -> int:
    score = 0
    if username in CONFIG["known_service_accounts"]:
        score -= 30  # legit service account, reduce suspicion

    unique_spns = data["unique_spn_count"]
    rc4_ratio = data["rc4_ratio"]
    off_hours = data["off_hours_count"]
    total = data["total_requests"]

    if unique_spns >= CONFIG["spn_request_threshold"]:
        score += min(unique_spns * 8, 40)

    if rc4_ratio >= CONFIG["rc4_ratio_threshold"]:
        score += 30

    auto = detect_automation(data["requests"])
    if auto["automated"]:
        score += 25

    if off_hours > 0:
        score += 15

    if unique_spns >= 10:
        score += 10  # mass harvesting

    return min(max(score, 0), 100)


def run_detection(user_data: dict) -> list:
    alerts = []
    for username, data in user_data.items():
        if data["total_requests"] < 3:
            continue
        score = score_kerberoasting(username, data)
        if score < 40:
            continue

        auto = detect_automation(data["requests"])
        severity = "CRITICAL" if score >= 75 else "HIGH" if score >= 55 else "MEDIUM"

        alerts.append({
            "alert_type": "KERBEROASTING_DETECTED",
            "severity": severity,
            "mitre_technique": "T1558.003",
            "mitre_tactic": "Credential Access",
            "username": username,
            "kerberoast_score": score,
            "unique_spns_requested": data["unique_spn_count"],
            "spns": data["spns"][:10],
            "total_requests": data["total_requests"],
            "rc4_requests": data["rc4_count"],
            "rc4_ratio": round(data["rc4_ratio"], 3),
            "automated": auto["automated"],
            "min_interval_ms": auto.get("min_interval_ms"),
            "off_hours_requests": data["off_hours_count"],
            "src_ips": data["src_ips"],
            "detection_timestamp": datetime.now(timezone.utc).isoformat(),
            "recommended_action": (
                f"Account '{username}' shows Kerberoasting indicators. "
                "Check if account is legitimately requesting these SPNs. "
                "Audit all SPN-registered service accounts — rotate passwords immediately. "
                "Enable AES-only encryption for service accounts (disable RC4). "
                "Review cracking activity on network (large DNS/HTTP traffic outbound). "
                "Consider honey-SPNs to detect future attacks."
            ),
        })

    alerts.sort(key=lambda x: x["kerberoast_score"], reverse=True)
    return alerts


def print_report(alerts: list):
    print("\n" + "═" * 70)
    print("  KERBEROASTING DETECTOR — CREDENTIAL THEFT REPORT")
    print("═" * 70)
    if not alerts:
        print("  ✅ No Kerberoasting activity detected.")
        return
    print(f"  🚨 {len(alerts)} suspicious account(s)\n")
    for i, a in enumerate(alerts, 1):
        print(f"  [{i}] {a['severity']} — Score: {a['kerberoast_score']}/100 | {a['username']}")
        print(f"      SPNs requested: {a['unique_spns_requested']} | RC4 ratio: {a['rc4_ratio']:.0%}")
        print(f"      Automated: {a['automated']} | Off-hours: {a['off_hours_requests']}")
        print(f"      Sample SPNs: {', '.join(a['spns'][:3])}")
        print(f"      MITRE: {a['mitre_technique']}")
        print()
    print("═" * 70)


def save_report(alerts, path):
    with open(path, "w") as f:
        json.dump({"total_alerts": len(alerts), "alerts": alerts}, f, indent=2)
    print(f"  📄 Report saved → {path}")


def main():
    log_path = sys.argv[1] if len(sys.argv) > 1 else "sample_kerberos.ndjson"
    out_path = sys.argv[2] if len(sys.argv) > 2 else "kerberoast_report.json"
    print(f"[*] Loading Kerberos event log: {log_path}")
    user_data = parse_event_log(log_path)
    print(f"[*] Unique users making TGS requests: {len(user_data)}")
    alerts = run_detection(user_data)
    print_report(alerts)
    save_report(alerts, out_path)


if __name__ == "__main__":
    main()
