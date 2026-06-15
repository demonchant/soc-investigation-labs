"""
Log Tampering Detector — Anti-Forensics & Log Integrity Analyzer
================================================================
Detects attackers clearing, tampering with, or disabling audit logs
to cover their tracks. Also detects sequence gaps, timestamp anomalies,
and suspicious event ID clusters that indicate covering of tracks.

MITRE ATT&CK:
  T1070     - Indicator Removal
  T1070.001 - Clear Windows Event Logs
  T1070.002 - Clear Linux or Mac System Logs
  T1562.002 - Disable Windows Event Logging
  T1562.006 - Indicator Blocking

Author: Oladapo Damilola (Wizardskull)
"""

import json
import statistics
import sys
from collections import defaultdict
from datetime import datetime, timezone


# ── Configuration ─────────────────────────────────────────────────────────────
CONFIG = {
    # Windows Event IDs indicating log manipulation
    "windows_tamper_event_ids": {
        1102: "Security audit log cleared",
        1100: "Event logging service shut down",
        104:  "System log cleared",
        517:  "Audit log cleared (legacy)",
        4719: "Audit policy changed",
        4906: "CrashOnAuditFail value changed",
        4907: "Auditing settings changed on object",
        7045: "New service installed (often used for persistence)",
    },
    # Linux syslog messages indicating log manipulation
    "linux_tamper_patterns": [
        r"logrotate", r"truncat", r"rm.*\.log", r"/var/log.*removed",
        r"auditctl.*-e\s+0", r"service.*auditd.*stop", r"systemctl.*stop.*auditd",
        r"echo.*>.*syslog", r"cat.*dev/null.*>.*auth\.log",
    ],
    # Gap thresholds
    "sequence_gap_threshold": 50,       # missing N+ sequential event IDs = suspicious
    "time_gap_threshold_minutes": 30,   # gap of N+ minutes in log = suspicious
    "burst_clear_window_seconds": 60,   # multiple clears in this window = critical
    "min_events_for_gap_analysis": 20,
}


# ── Windows Event Analysis ────────────────────────────────────────────────────
def analyze_windows_events(events: list) -> list:
    """Detect Windows log tampering via event ID and sequence analysis."""
    alerts = []
    event_ids = defaultdict(list)
    timestamps = []

    for event in events:
        eid = event.get("event_id")
        ts = event.get("ts", 0)
        if eid:
            event_ids[eid].append(event)
        timestamps.append(ts)

    # 1. Direct tamper event IDs
    for eid, evts in event_ids.items():
        if eid in CONFIG["windows_tamper_event_ids"]:
            description = CONFIG["windows_tamper_event_ids"][eid]

            # Burst detection: multiple clears in short window
            if len(evts) > 1:
                time_range = max(e["ts"] for e in evts) - min(e["ts"] for e in evts)
                if time_range < CONFIG["burst_clear_window_seconds"]:
                    alerts.append({
                        "type": "LOG_CLEAR_BURST",
                        "severity": "CRITICAL",
                        "event_id": eid,
                        "description": f"BURST: {description} — {len(evts)} times in {time_range:.0f}s",
                        "count": len(evts),
                        "hosts": list({e.get("host", "") for e in evts}),
                        "first_seen": datetime.fromtimestamp(evts[0]["ts"], tz=timezone.utc).isoformat(),
                    })
                    continue

            for evt in evts:
                alerts.append({
                    "type": "LOG_TAMPER_EVENT",
                    "severity": "CRITICAL" if eid in (1102, 104, 4719) else "HIGH",
                    "event_id": eid,
                    "description": description,
                    "host": evt.get("host", "unknown"),
                    "user": evt.get("user", "unknown"),
                    "event_time": datetime.fromtimestamp(evt["ts"], tz=timezone.utc).isoformat(),
                })

    # 2. Sequence number gap analysis (Windows logs have sequential record IDs)
    record_ids = sorted([e.get("record_id") for e in events if e.get("record_id")])
    if len(record_ids) >= CONFIG["min_events_for_gap_analysis"]:
        gaps = []
        for i in range(1, len(record_ids)):
            gap = record_ids[i] - record_ids[i - 1]
            if gap > CONFIG["sequence_gap_threshold"]:
                gaps.append({
                    "start_id": record_ids[i - 1],
                    "end_id": record_ids[i],
                    "missing_count": gap - 1,
                })

        if gaps:
            total_missing = sum(g["missing_count"] for g in gaps)
            alerts.append({
                "type": "SEQUENCE_GAP",
                "severity": "HIGH",
                "description": f"Missing {total_missing} event log records across {len(gaps)} gap(s)",
                "gaps": gaps[:5],  # top 5 largest gaps
                "total_missing": total_missing,
                "analysis": "Gaps in sequential record IDs indicate log entries were deleted",
            })

    # 3. Timestamp anomalies: events out of order can indicate injection
    if len(timestamps) >= 10:
        sorted_ts = sorted(timestamps)
        out_of_order = sum(1 for i in range(1, len(timestamps))
                          if timestamps[i] < timestamps[i - 1])
        if out_of_order > len(timestamps) * 0.05:  # >5% out of order
            alerts.append({
                "type": "TIMESTAMP_ANOMALY",
                "severity": "MEDIUM",
                "description": f"{out_of_order} events ({out_of_order/len(timestamps):.0%}) have timestamps out of chronological order",
                "out_of_order_count": out_of_order,
                "analysis": "May indicate log injection, timezone manipulation, or NTP attack",
            })

    # 4. Time gap analysis: big quiet periods
    if len(timestamps) >= CONFIG["min_events_for_gap_analysis"]:
        sorted_ts = sorted(timestamps)
        time_gaps = [(sorted_ts[i + 1] - sorted_ts[i]) / 60
                     for i in range(len(sorted_ts) - 1)]
        big_gaps = [(i, g) for i, g in enumerate(time_gaps)
                    if g >= CONFIG["time_gap_threshold_minutes"]]

        if big_gaps:
            for idx, gap_minutes in big_gaps:
                gap_start = datetime.fromtimestamp(sorted_ts[idx], tz=timezone.utc).isoformat()
                gap_end = datetime.fromtimestamp(sorted_ts[idx + 1], tz=timezone.utc).isoformat()
                alerts.append({
                    "type": "LOG_SILENCE_GAP",
                    "severity": "MEDIUM",
                    "description": f"{gap_minutes:.0f}-minute gap in logs between {gap_start} and {gap_end}",
                    "gap_start": gap_start,
                    "gap_end": gap_end,
                    "gap_minutes": round(gap_minutes, 1),
                    "analysis": "Unexplained log silence may indicate service disruption or log clearing",
                })

    return alerts


# ── Linux Log Analysis ────────────────────────────────────────────────────────
def analyze_linux_events(events: list) -> list:
    """Detect Linux log tampering via command analysis."""
    import re
    alerts = []
    patterns = CONFIG["linux_tamper_patterns"]

    for event in events:
        cmdline = event.get("command_line", "") + " " + event.get("message", "")
        for pattern in patterns:
            if re.search(pattern, cmdline, re.IGNORECASE):
                alerts.append({
                    "type": "LINUX_LOG_TAMPER",
                    "severity": "HIGH",
                    "description": f"Suspicious log manipulation command matched: {pattern}",
                    "host": event.get("host", "unknown"),
                    "user": event.get("user", "unknown"),
                    "command": cmdline[:200],
                    "matched_pattern": pattern,
                    "event_time": datetime.fromtimestamp(
                        event.get("ts", 0), tz=timezone.utc).isoformat(),
                })
                break  # one match per event

    return alerts


# ── Log Parser ────────────────────────────────────────────────────────────────
def parse_event_log(log_path: str) -> tuple:
    """Parse combined Windows/Linux event log (NDJSON)."""
    windows_events = []
    linux_events = []

    with open(log_path, "r") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                event = json.loads(line)
                ts_raw = event.get("timestamp", 0)
                if isinstance(ts_raw, (int, float)):
                    ts = float(ts_raw)
                else:
                    ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00")).timestamp()
                event["ts"] = ts

                os_type = event.get("os", "windows").lower()
                if os_type == "linux":
                    linux_events.append(event)
                else:
                    windows_events.append(event)

            except (json.JSONDecodeError, KeyError, ValueError) as e:
                print(f"[WARN] Line {line_num}: {e}", file=sys.stderr)

    return windows_events, linux_events


# ── Unified Detection Runner ──────────────────────────────────────────────────
def run_detection(windows_events: list, linux_events: list) -> list:
    all_alerts = []

    win_alerts = analyze_windows_events(windows_events)
    lin_alerts = analyze_linux_events(linux_events)

    # Enrich all alerts
    for alert in win_alerts + lin_alerts:
        alert.setdefault("mitre_tactic", "Defense Evasion")
        alert.setdefault("mitre_technique", "T1070")
        alert["detection_timestamp"] = datetime.now(timezone.utc).isoformat()
        alert.setdefault("recommended_action",
            "CRITICAL: Preserve current log state immediately. "
            "Pull logs from SIEM/SOAR (not host). "
            "Treat all evidence on this host as potentially compromised. "
            "Escalate to IR team — attacker may have achieved persistence.")
        all_alerts.append(alert)

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    all_alerts.sort(key=lambda x: severity_order.get(x.get("severity", "MEDIUM"), 9))
    return all_alerts


# ── Reporting ─────────────────────────────────────────────────────────────────
def print_report(alerts: list, win_count: int, lin_count: int):
    print("\n" + "═" * 70)
    print("  LOG TAMPERING DETECTOR — INTEGRITY ANALYSIS REPORT")
    print("═" * 70)
    print(f"  Windows events: {win_count} | Linux events: {lin_count}")

    if not alerts:
        print("  ✅ No log tampering indicators detected.")
        return

    critical = sum(1 for a in alerts if a.get("severity") == "CRITICAL")
    print(f"  🚨 {len(alerts)} tampering indicator(s): {critical} CRITICAL\n")

    for i, a in enumerate(alerts, 1):
        print(f"  [{i}] {a.get('severity', '?')} — {a['type']}")
        print(f"      {a['description']}")
        if "host" in a:
            print(f"      Host: {a['host']} | User: {a.get('user', 'N/A')}")
        if "total_missing" in a:
            print(f"      Missing records: {a['total_missing']}")
        print(f"      MITRE: {a.get('mitre_technique', 'T1070')}")
        print()
    print("═" * 70)


def save_report(alerts: list, output_path: str):
    with open(output_path, "w") as f:
        json.dump({"total_alerts": len(alerts), "alerts": alerts}, f, indent=2)
    print(f"  📄 Report saved → {output_path}")


def main():
    log_path = sys.argv[1] if len(sys.argv) > 1 else "sample_event_logs.ndjson"
    output_path = sys.argv[2] if len(sys.argv) > 2 else "log_tamper_report.json"
    print(f"[*] Loading event log: {log_path}")
    windows_events, linux_events = parse_event_log(log_path)
    print(f"[*] Windows events: {len(windows_events)} | Linux events: {len(linux_events)}")
    alerts = run_detection(windows_events, linux_events)
    print_report(alerts, len(windows_events), len(linux_events))
    save_report(alerts, output_path)


if __name__ == "__main__":
    main()
