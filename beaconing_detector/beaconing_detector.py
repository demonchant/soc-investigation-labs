"""
Beaconing Detector — C2 Communication Pattern Analyzer
=======================================================
Detects periodic/beaconing network connections that indicate C2 malware activity.
Uses statistical analysis (standard deviation, coefficient of variation, regularity scoring)
on connection intervals to identify hosts communicating on suspiciously regular schedules.

MITRE ATT&CK:
  T1071 - Application Layer Protocol
  T1571 - Non-Standard Port
  T1102 - Web Service (C2 via web services)
  T1008 - Fallback Channels

Author: Oladapo Damilola (Wizardskull)
Role Target: SOC L2/L3 | Detection Engineer
"""

import json
import math
import statistics
import sys
from collections import defaultdict
from datetime import datetime, timezone


# ── Configuration ────────────────────────────────────────────────────────────
CONFIG = {
    "min_connections": 5,           # minimum connections to analyse
    "cv_threshold": 0.30,           # coefficient of variation threshold (lower = more regular = suspicious)
    "beacon_score_threshold": 70,   # 0–100 score; >=70 flagged as beacon
    "jitter_window_pct": 0.20,      # allow ±20% jitter (common in Cobalt Strike, Metasploit)
    "top_ports_whitelist": {80, 443, 53},  # common ports reduce suspicion weight
    "known_good_hosts": {           # allowlist — reduce false positives
        "updates.microsoft.com",
        "ocsp.digicert.com",
        "telemetry.apple.com",
    },
}


# ── Data Structures ───────────────────────────────────────────────────────────
class BeaconCandidate:
    def __init__(self, src_ip, dst_ip, dst_port, dst_host=""):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.dst_host = dst_host
        self.timestamps = []

    def add_event(self, ts: float):
        self.timestamps.append(ts)

    def intervals(self):
        sorted_ts = sorted(self.timestamps)
        return [sorted_ts[i + 1] - sorted_ts[i] for i in range(len(sorted_ts) - 1)]

    def key(self):
        return f"{self.src_ip}→{self.dst_ip}:{self.dst_port}"


# ── Statistical Engine ────────────────────────────────────────────────────────
def coefficient_of_variation(values: list) -> float:
    """CV = stdev / mean. Low CV = highly regular = suspicious."""
    if len(values) < 2:
        return 1.0  # not enough data
    mean = statistics.mean(values)
    if mean == 0:
        return 0.0
    return statistics.stdev(values) / mean


def jitter_score(intervals: list, jitter_pct: float) -> float:
    """
    Fraction of intervals falling within ±jitter_pct of median.
    High fraction = malware-like regularity.
    """
    if not intervals:
        return 0.0
    median = statistics.median(intervals)
    low = median * (1 - jitter_pct)
    high = median * (1 + jitter_pct)
    in_window = sum(1 for i in intervals if low <= i <= high)
    return in_window / len(intervals)


def beacon_score(candidate: BeaconCandidate) -> dict:
    """
    Composite scoring engine — returns 0–100 score with evidence breakdown.
    """
    intervals = candidate.intervals()
    if len(intervals) < CONFIG["min_connections"] - 1:
        return {"score": 0, "reason": "insufficient_data"}

    cv = coefficient_of_variation(intervals)
    jitter = jitter_score(intervals, CONFIG["jitter_window_pct"])
    mean_interval = statistics.mean(intervals)
    connection_count = len(candidate.timestamps)

    # Score components (weighted)
    regularity_score = max(0, (1 - cv)) * 40          # 40 pts: how regular
    jitter_score_val = jitter * 30                      # 30 pts: how many in jitter window
    volume_score = min(connection_count / 20, 1) * 20  # 20 pts: connection volume
    port_penalty = 0
    if candidate.dst_port not in CONFIG["top_ports_whitelist"]:
        port_penalty = 10                               # 10 pts: non-standard port

    total = regularity_score + jitter_score_val + volume_score + port_penalty

    # Allowlist suppression
    if candidate.dst_host in CONFIG["known_good_hosts"]:
        total *= 0.1  # 90% penalty for known-good hosts

    return {
        "score": round(min(total, 100), 2),
        "cv": round(cv, 4),
        "jitter_fraction": round(jitter, 4),
        "mean_interval_sec": round(mean_interval, 2),
        "connection_count": connection_count,
        "regularity_score": round(regularity_score, 2),
        "jitter_score": round(jitter_score_val, 2),
        "volume_score": round(volume_score, 2),
        "port_bonus": port_penalty,
    }


# ── Log Parser ────────────────────────────────────────────────────────────────
def parse_netflow_log(log_path: str) -> dict:
    """
    Parse NDJSON netflow/proxy logs.
    Expected fields: timestamp, src_ip, dst_ip, dst_port, dst_host (optional)
    """
    candidates = defaultdict(lambda: None)

    with open(log_path, "r") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                event = json.loads(line)
                src = event["src_ip"]
                dst = event["dst_ip"]
                port = int(event.get("dst_port", 0))
                host = event.get("dst_host", "")
                ts_raw = event["timestamp"]

                # Parse ISO8601 or epoch
                if isinstance(ts_raw, (int, float)):
                    ts = float(ts_raw)
                else:
                    dt = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                    ts = dt.timestamp()

                key = f"{src}→{dst}:{port}"
                if candidates[key] is None:
                    candidates[key] = BeaconCandidate(src, dst, port, host)
                candidates[key].add_event(ts)

            except (json.JSONDecodeError, KeyError, ValueError) as e:
                print(f"[WARN] Line {line_num} skipped: {e}", file=sys.stderr)

    return dict(candidates)


# ── Detection Engine ──────────────────────────────────────────────────────────
def run_detection(candidates: dict) -> list:
    alerts = []
    for key, candidate in candidates.items():
        result = beacon_score(candidate)
        if result.get("score", 0) >= CONFIG["beacon_score_threshold"]:
            alert = {
                "alert_type": "BEACONING_DETECTED",
                "severity": "HIGH" if result["score"] >= 85 else "MEDIUM",
                "mitre_tactic": "Command and Control",
                "mitre_technique": "T1071 / T1571",
                "src_ip": candidate.src_ip,
                "dst_ip": candidate.dst_ip,
                "dst_port": candidate.dst_port,
                "dst_host": candidate.dst_host,
                "beacon_score": result["score"],
                "mean_interval_sec": result["mean_interval_sec"],
                "cv": result["cv"],
                "jitter_fraction": result["jitter_fraction"],
                "connection_count": result["connection_count"],
                "evidence": result,
                "detection_timestamp": datetime.now(timezone.utc).isoformat(),
                "recommended_action": (
                    "Isolate host and capture full PCAP. "
                    "Cross-reference dst_ip with threat intel feeds. "
                    "Check for process making connection (EDR pivot)."
                ),
            }
            alerts.append(alert)

    # Sort by score descending
    alerts.sort(key=lambda x: x["beacon_score"], reverse=True)
    return alerts


# ── Reporting ─────────────────────────────────────────────────────────────────
def print_report(alerts: list):
    print("\n" + "═" * 70)
    print("  BEACONING DETECTOR — THREAT REPORT")
    print("═" * 70)

    if not alerts:
        print("  ✅ No beaconing activity detected.")
        return

    print(f"  🚨 {len(alerts)} beaconing host(s) detected\n")
    for i, alert in enumerate(alerts, 1):
        print(f"  [{i}] {alert['severity']} — Score: {alert['beacon_score']}/100")
        print(f"      {alert['src_ip']} → {alert['dst_ip']}:{alert['dst_port']}", end="")
        if alert["dst_host"]:
            print(f" ({alert['dst_host']})", end="")
        print()
        print(f"      Interval: {alert['mean_interval_sec']}s avg | CV: {alert['cv']} | Jitter: {alert['jitter_fraction']:.0%} in window")
        print(f"      Connections: {alert['connection_count']} | MITRE: {alert['mitre_technique']}")
        print(f"      Action: {alert['recommended_action']}")
        print()

    print("═" * 70)


def save_report(alerts: list, output_path: str):
    with open(output_path, "w") as f:
        json.dump({"total_alerts": len(alerts), "alerts": alerts}, f, indent=2)
    print(f"  📄 Full JSON report saved → {output_path}")


# ── Entry Point ───────────────────────────────────────────────────────────────
def main():
    log_path = sys.argv[1] if len(sys.argv) > 1 else "sample_netflow.ndjson"
    output_path = sys.argv[2] if len(sys.argv) > 2 else "beacon_report.json"

    print(f"[*] Loading netflow log: {log_path}")
    candidates = parse_netflow_log(log_path)
    print(f"[*] Unique src→dst:port pairs analysed: {len(candidates)}")

    alerts = run_detection(candidates)
    print_report(alerts)
    save_report(alerts, output_path)


if __name__ == "__main__":
    main()
