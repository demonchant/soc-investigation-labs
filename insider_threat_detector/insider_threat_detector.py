"""
Insider Threat Detector — Behavioral Baseline & Data Hoarding Analyzer
======================================================================
Detects malicious insider activity by building per-user behavioral
baselines and flagging deviations: off-hours access, mass downloads,
privilege abuse, data staging, and communication with competitors.

Insider threats are the hardest to detect because they use legitimate
credentials and have legitimate access. This tool detects the BEHAVIOR
that distinguishes malicious from normal activity.

MITRE ATT&CK:
  T1078     - Valid Accounts (insider using own credentials)
  T1074     - Data Staged
  T1048     - Exfiltration Over Alt Protocol
  T1567     - Exfiltration Over Web Service
  T1213     - Data from Information Repositories

Author: Oladapo Damilola (Wizardskull)
"""

import json
import math
import statistics
import sys
from collections import defaultdict
from datetime import datetime, timezone


CONFIG = {
    "baseline_days": 30,
    "off_hours": (20, 7),               # 8 PM – 7 AM
    "weekend_days": {5, 6},             # Saturday=5, Sunday=6
    "mass_download_threshold_mb": 500,  # >500MB in a session = data hoarding
    "file_access_spike_multiplier": 5,  # 5x baseline file access rate = anomaly
    "failed_access_threshold": 20,      # repeated access denied = privilege abuse
    "sensitive_path_patterns": [
        r"\\finance\\", r"\\payroll\\", r"\\hr\\", r"\\legal\\",
        r"\\executive\\", r"\\board\\", r"\\acquisition\\",
        r"/finance/", r"/payroll/", r"/hr/",
        r"salary", r"compensation", r"bonus",
        r"merger", r"acquisition", r"strategic_plan",
        r"customer_list", r"client_data",
    ],
    "cloud_storage_domains": [
        "dropbox.com", "box.com", "drive.google.com",
        "onedrive.live.com", "wetransfer.com",
        "mega.nz", "mediafire.com", "anonfiles.com",
        "gofile.io", "sendspace.com",
    ],
    "competitor_domains": [],           # populate with org-specific competitors
    "resignation_risk_window_days": 90, # flag users who may be leaving (high risk)
}


def parse_activity_log(log_path: str) -> dict:
    """
    Parse multi-source user activity log (NDJSON).
    event_type: file_access | web_request | auth | email | print
    """
    user_data = defaultdict(lambda: {
        "file_accesses": [],
        "web_requests": [],
        "auth_events": [],
        "print_jobs": [],
        "download_bytes": 0,
        "failed_access_count": 0,
        "sensitive_file_accesses": [],
        "cloud_uploads": [],
        "off_hours_events": [],
        "timestamps": [],
    })

    with open(log_path) as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                ev = json.loads(line)
                ts_raw = ev.get("timestamp", 0)
                ts = float(ts_raw) if isinstance(ts_raw, (int, float)) else \
                    datetime.fromisoformat(ts_raw.replace("Z", "+00:00")).timestamp()
                ev["ts"] = ts
                username = ev.get("username", "unknown").lower()
                d = user_data[username]
                d["timestamps"].append(ts)

                dt = datetime.fromtimestamp(ts, tz=timezone.utc)
                is_off_hours = dt.hour >= CONFIG["off_hours"][0] or dt.hour < CONFIG["off_hours"][1]
                is_weekend = dt.weekday() in CONFIG["weekend_days"]

                if is_off_hours or is_weekend:
                    d["off_hours_events"].append(ev)

                event_type = ev.get("event_type", "")

                if event_type == "file_access":
                    path = ev.get("file_path", "")
                    action = ev.get("action", "")
                    size = ev.get("file_size_bytes", 0)
                    d["file_accesses"].append(ev)

                    if action == "denied":
                        d["failed_access_count"] += 1

                    import re
                    for pat in CONFIG["sensitive_path_patterns"]:
                        if re.search(pat, path, re.IGNORECASE):
                            d["sensitive_file_accesses"].append(ev)
                            break

                    if action in ("read", "download", "copy"):
                        d["download_bytes"] += size

                elif event_type == "web_request":
                    domain = ev.get("domain", "")
                    bytes_up = ev.get("bytes_uploaded", 0)
                    d["web_requests"].append(ev)

                    if any(cd in domain.lower() for cd in CONFIG["cloud_storage_domains"]):
                        d["cloud_uploads"].append({
                            "domain": domain, "bytes": bytes_up, "ts": ts
                        })

                elif event_type == "print":
                    d["print_jobs"].append(ev)

                elif event_type == "auth":
                    d["auth_events"].append(ev)

            except (json.JSONDecodeError, KeyError, ValueError) as e:
                print(f"[WARN] Line {line_num}: {e}", file=sys.stderr)

    return dict(user_data)


def build_baseline(data: dict) -> dict:
    """Compute baseline stats per user for anomaly comparison."""
    baselines = {}
    for username, d in data.items():
        file_count = len(d["file_accesses"])
        web_count = len(d["web_requests"])
        duration_days = max(
            (max(d["timestamps"]) - min(d["timestamps"])) / 86400, 1
        ) if len(d["timestamps"]) >= 2 else 1

        baselines[username] = {
            "avg_file_accesses_per_day": file_count / duration_days,
            "avg_web_requests_per_day": web_count / duration_days,
            "avg_download_mb_per_day": (d["download_bytes"] / 1_000_000) / duration_days,
            "off_hours_ratio": len(d["off_hours_events"]) / max(len(d["timestamps"]), 1),
        }
    return baselines


def score_insider_risk(username: str, data: dict, baseline: dict) -> dict:
    import re
    score = 0
    indicators = []
    b = baseline.get(username, {})

    # 1. Mass data download
    download_mb = data["download_bytes"] / 1_000_000
    if download_mb >= CONFIG["mass_download_threshold_mb"]:
        score += 30
        indicators.append(f"mass download: {download_mb:.0f} MB")

    # 2. Off-hours activity spike
    off_ratio = len(data["off_hours_events"]) / max(len(data["timestamps"]), 1)
    baseline_off = b.get("off_hours_ratio", 0.1)
    if off_ratio > baseline_off * 3 and len(data["off_hours_events"]) > 5:
        score += 20
        indicators.append(f"off-hours spike: {off_ratio:.0%} of activity (baseline: {baseline_off:.0%})")

    # 3. Sensitive file access surge
    if len(data["sensitive_file_accesses"]) >= 10:
        score += 25
        indicators.append(f"sensitive file accesses: {len(data['sensitive_file_accesses'])}")

    # 4. Cloud storage uploads (potential exfiltration)
    if data["cloud_uploads"]:
        total_cloud_bytes = sum(c["bytes"] for c in data["cloud_uploads"])
        cloud_mb = total_cloud_bytes / 1_000_000
        score += 25
        domains = list({c["domain"] for c in data["cloud_uploads"]})
        indicators.append(f"cloud storage upload: {cloud_mb:.0f} MB to {', '.join(domains[:2])}")

    # 5. Repeated access denied (probing for data they don't have rights to)
    if data["failed_access_count"] >= CONFIG["failed_access_threshold"]:
        score += 15
        indicators.append(f"repeated access denied: {data['failed_access_count']} times")

    # 6. Print job spike (paper-based exfiltration)
    if len(data["print_jobs"]) >= 20:
        score += 15
        pages = sum(j.get("pages", 1) for j in data["print_jobs"])
        indicators.append(f"high print volume: {len(data['print_jobs'])} jobs, {pages} pages")

    # 7. File access rate spike vs baseline
    file_per_day = b.get("avg_file_accesses_per_day", 0)
    current_file_rate = len(data["file_accesses"])
    if file_per_day > 0 and current_file_rate > file_per_day * CONFIG["file_access_spike_multiplier"]:
        score += 20
        indicators.append(f"file access spike: {current_file_rate} vs baseline {file_per_day:.0f}/day")

    return {"score": min(score, 100), "indicators": indicators}


def run_detection(user_data: dict) -> list:
    alerts = []
    baselines = build_baseline(user_data)

    for username, data in user_data.items():
        if len(data["timestamps"]) < 5:
            continue

        result = score_insider_risk(username, data, baselines)
        if result["score"] < 30:
            continue

        severity = "CRITICAL" if result["score"] >= 75 else \
                   "HIGH" if result["score"] >= 50 else "MEDIUM"

        alerts.append({
            "alert_type": "INSIDER_THREAT_DETECTED",
            "severity": severity,
            "mitre_technique": "T1078 / T1074 / T1567",
            "mitre_tactic": "Exfiltration / Collection",
            "username": username,
            "risk_score": result["score"],
            "indicators": result["indicators"],
            "total_events": len(data["timestamps"]),
            "off_hours_events": len(data["off_hours_events"]),
            "sensitive_files_accessed": len(data["sensitive_file_accesses"]),
            "cloud_upload_events": len(data["cloud_uploads"]),
            "download_mb": round(data["download_bytes"] / 1_000_000, 1),
            "failed_access_attempts": data["failed_access_count"],
            "print_jobs": len(data["print_jobs"]),
            "detection_timestamp": datetime.now(timezone.utc).isoformat(),
            "recommended_action": (
                f"Initiate confidential HR/Legal review for '{username}'. "
                "Preserve all logs before notifying user. "
                "Check DLP alerts and email archive for data transfers. "
                "Review building access logs for unusual hours. "
                "DO NOT alert user — conduct covert investigation first."
            ),
        })

    alerts.sort(key=lambda x: x["risk_score"], reverse=True)
    return alerts


def print_report(alerts: list):
    print("\n" + "═" * 70)
    print("  INSIDER THREAT DETECTOR — BEHAVIORAL ANOMALY REPORT")
    print("═" * 70)
    if not alerts:
        print("  ✅ No insider threat indicators detected.")
        return
    print(f"  🚨 {len(alerts)} high-risk user(s)\n")
    for i, a in enumerate(alerts, 1):
        print(f"  [{i}] {a['severity']} — Risk: {a['risk_score']}/100 | {a['username']}")
        for ind in a["indicators"]:
            print(f"      ⚠ {ind}")
        print(f"      Download: {a['download_mb']} MB | Off-hours: {a['off_hours_events']} events")
        print(f"      MITRE: {a['mitre_technique']}")
        print()
    print("═" * 70)


def save_report(alerts, path):
    with open(path, "w") as f:
        json.dump({"total_alerts": len(alerts), "alerts": alerts}, f, indent=2)
    print(f"  📄 Report saved → {path}")


def main():
    log_path = sys.argv[1] if len(sys.argv) > 1 else "sample_user_activity.ndjson"
    out_path = sys.argv[2] if len(sys.argv) > 2 else "insider_threat_report.json"
    print(f"[*] Loading user activity log: {log_path}")
    user_data = parse_activity_log(log_path)
    print(f"[*] Unique users: {len(user_data)}")
    alerts = run_detection(user_data)
    print_report(alerts)
    save_report(alerts, out_path)


if __name__ == "__main__":
    main()
