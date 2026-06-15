"""
Privilege Escalation Detector — Token & Permission Abuse Analyzer
=================================================================
Detects Windows and Linux privilege escalation attempts by monitoring:
  - Suspicious process token manipulation
  - SUID/SGID abuse on Linux
  - UAC bypass techniques
  - Token impersonation (T1134)
  - Sudo abuse patterns
  - Service path hijacking indicators

MITRE ATT&CK:
  T1134     - Access Token Manipulation
  T1134.001 - Token Impersonation/Theft
  T1548     - Abuse Elevation Control Mechanism
  T1548.002 - Bypass User Account Control
  T1068     - Exploitation for Privilege Escalation
  T1574     - Hijack Execution Flow

Author: Oladapo Damilola (Wizardskull)
"""

import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone


# ── Detection Rules ───────────────────────────────────────────────────────────
WINDOWS_PRIVESC_RULES = [
    # ── UAC Bypass Techniques ─────────────────────────────────────────────────
    {
        "id": "WIN-PRIVESC-001",
        "name": "UAC Bypass via fodhelper.exe",
        "mitre": "T1548.002",
        "severity": "CRITICAL",
        "process_match": "fodhelper.exe",
        "parent_process_match": None,
        "cmdline_patterns": [],
        "registry_patterns": [r"HKCU.*Classes.*ms-settings.*shell.*open.*command"],
        "description": "fodhelper.exe UAC bypass — attacker sets HKCU registry key to execute arbitrary commands elevated",
    },
    {
        "id": "WIN-PRIVESC-002",
        "name": "UAC Bypass via eventvwr.exe",
        "mitre": "T1548.002",
        "severity": "CRITICAL",
        "process_match": "eventvwr.exe",
        "parent_process_match": None,
        "cmdline_patterns": [r"cmd\.exe", r"powershell"],
        "description": "eventvwr.exe spawning cmd/powershell — classic UAC bypass technique",
    },
    {
        "id": "WIN-PRIVESC-003",
        "name": "UAC Bypass via sdclt.exe",
        "mitre": "T1548.002",
        "severity": "CRITICAL",
        "process_match": "sdclt.exe",
        "cmdline_patterns": [r"/kickoffelev"],
        "description": "sdclt.exe UAC bypass via /kickoffelev parameter",
    },

    # ── Token Manipulation ────────────────────────────────────────────────────
    {
        "id": "WIN-PRIVESC-004",
        "name": "Token Impersonation via CreateProcessWithTokenW",
        "mitre": "T1134.001",
        "severity": "HIGH",
        "process_match": None,
        "cmdline_patterns": [r"SeImpersonatePrivilege", r"SeAssignPrimaryTokenPrivilege"],
        "event_ids": [4672, 4673],  # Special privilege use
        "description": "SeImpersonatePrivilege assignment — common in PrintSpoofer, JuicyPotato, etc.",
    },
    {
        "id": "WIN-PRIVESC-005",
        "name": "Suspicious Integrity Level Escalation",
        "mitre": "T1134",
        "severity": "HIGH",
        "process_match": None,
        "event_ids": [4688],
        "cmdline_patterns": [r"whoami.*priv", r"whoami.*groups"],
        "description": "Privilege enumeration following escalation — common post-UAC step",
    },

    # ── Service Abuse ─────────────────────────────────────────────────────────
    {
        "id": "WIN-PRIVESC-006",
        "name": "Unquoted Service Path Exploitation",
        "mitre": "T1574.009",
        "severity": "HIGH",
        "process_match": None,
        "cmdline_patterns": [r"sc\s+create", r"sc\s+config"],
        "registry_patterns": [r"SYSTEM\\CurrentControlSet\\Services"],
        "description": "Service creation/modification — may be exploiting unquoted service paths",
    },
    {
        "id": "WIN-PRIVESC-007",
        "name": "AlwaysInstallElevated MSI Exploit",
        "mitre": "T1548.002",
        "severity": "CRITICAL",
        "process_match": "msiexec.exe",
        "cmdline_patterns": [r"/quiet.*install", r"http.*\.msi", r"\\\\.*\.msi"],
        "description": "msiexec with AlwaysInstallElevated policy — installs with SYSTEM privileges",
    },

    # ── Credential-based Escalation ───────────────────────────────────────────
    {
        "id": "WIN-PRIVESC-008",
        "name": "RunAs / Credential Relay Escalation",
        "mitre": "T1134.002",
        "severity": "HIGH",
        "process_match": None,
        "cmdline_patterns": [r"runas\s+/user:.*administrator", r"runas\s+/netonly",
                              r"runas\s+/user:.*\\Administrator"],
        "description": "RunAs with admin credentials — may indicate credential theft",
    },

    # ── Kernel Exploitation Indicators ────────────────────────────────────────
    {
        "id": "WIN-PRIVESC-009",
        "name": "Driver Load for Kernel Exploit",
        "mitre": "T1068",
        "severity": "CRITICAL",
        "process_match": None,
        "event_ids": [6,  # driver load
                      7045],  # service installed
        "cmdline_patterns": [r"\.sys\b", r"DriverEntry"],
        "description": "Suspicious driver load — may be BYOVD (Bring Your Own Vulnerable Driver) attack",
    },
]

LINUX_PRIVESC_RULES = [
    {
        "id": "LIN-PRIVESC-001",
        "name": "SUID Binary Abuse",
        "mitre": "T1548.001",
        "severity": "HIGH",
        "cmdline_patterns": [r"find.*-perm.*-u=s", r"find.*-perm.*4000",
                              r"find.*-suid", r"find.*-perm\s+-4000"],
        "description": "SUID binary enumeration — attacker looking for SUID escalation path",
    },
    {
        "id": "LIN-PRIVESC-002",
        "name": "Sudo -l Enumeration",
        "mitre": "T1548.003",
        "severity": "MEDIUM",
        "cmdline_patterns": [r"sudo\s+-l\b", r"sudo\s+--list"],
        "description": "Listing sudo permissions — attacker mapping escalation opportunities",
    },
    {
        "id": "LIN-PRIVESC-003",
        "name": "GTFOBins Sudo Escape",
        "mitre": "T1548.003",
        "severity": "CRITICAL",
        "cmdline_patterns": [
            r"sudo.*vim.*-c.*!.*sh",
            r"sudo.*python.*-c.*import.*pty",
            r"sudo.*nmap.*--interactive",
            r"sudo.*less.*!/bin/sh",
            r"sudo.*man.*!/bin/sh",
            r"sudo.*find.*-exec.*sh",
            r"sudo.*awk.*BEGIN.*system",
            r"sudo.*perl.*-e.*exec.*sh",
            r"sudo.*env\s+/bin",
        ],
        "description": "GTFOBins sudo escape pattern — executing shell through allowed sudo binary",
    },
    {
        "id": "LIN-PRIVESC-004",
        "name": "Cron Job Hijacking",
        "mitre": "T1053.003",
        "severity": "HIGH",
        "cmdline_patterns": [r"echo.*>.*crontab", r"crontab.*-e",
                              r">\s*/etc/cron", r">\s*/var/spool/cron"],
        "description": "Writing to cron — may be hijacking existing root cron job",
    },
    {
        "id": "LIN-PRIVESC-005",
        "name": "LD_PRELOAD Privilege Escalation",
        "mitre": "T1574.006",
        "severity": "CRITICAL",
        "cmdline_patterns": [r"LD_PRELOAD=", r"LD_LIBRARY_PATH.*sudo"],
        "description": "LD_PRELOAD injection — loading malicious shared library for escalation",
    },
    {
        "id": "LIN-PRIVESC-006",
        "name": "Capabilities Enumeration",
        "mitre": "T1548",
        "severity": "MEDIUM",
        "cmdline_patterns": [r"getcap\s+-r", r"getcap.*\/"],
        "description": "Linux capabilities enumeration — searching for cap_setuid or cap_net_admin",
    },
    {
        "id": "LIN-PRIVESC-007",
        "name": "Docker Escape Attempt",
        "mitre": "T1611",
        "severity": "CRITICAL",
        "cmdline_patterns": [r"docker.*-v\s+/:/", r"--privileged.*docker",
                              r"nsenter.*-t\s+1", r"mount.*cgroup"],
        "description": "Container escape via privileged Docker or cgroup mount",
    },
    {
        "id": "LIN-PRIVESC-008",
        "name": "Writable /etc/passwd Exploitation",
        "mitre": "T1098",
        "severity": "CRITICAL",
        "cmdline_patterns": [r"echo.*root.*:.*0:0.*>>.*passwd",
                              r"openssl.*passwd.*>>.*passwd",
                              r"echo.*::0:0.*>>/etc/passwd"],
        "description": "Writing root-equivalent entry to /etc/passwd",
    },
]


# ── Log Parser ────────────────────────────────────────────────────────────────
def parse_process_events(log_path: str) -> list:
    events = []
    with open(log_path, "r") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                event = json.loads(line)
                ts_raw = event.get("timestamp", 0)
                ts = float(ts_raw) if isinstance(ts_raw, (int, float)) else \
                    datetime.fromisoformat(ts_raw.replace("Z", "+00:00")).timestamp()
                event["ts"] = ts
                events.append(event)
            except (json.JSONDecodeError, KeyError, ValueError) as e:
                print(f"[WARN] Line {line_num}: {e}", file=sys.stderr)
    return events


# ── Detection Engine ──────────────────────────────────────────────────────────
def match_windows_rules(event: dict) -> list:
    cmdline = (event.get("command_line", "") + " " + event.get("message", "")).lower()
    proc = event.get("process_name", "").lower().split("\\")[-1]
    parent = event.get("parent_process", "").lower().split("\\")[-1]
    event_id = event.get("event_id")
    hits = []

    for rule in WINDOWS_PRIVESC_RULES:
        matched = False

        if rule.get("process_match") and proc != rule["process_match"].lower():
            # If process must match but doesn't, check cmdline patterns first
            if not rule.get("cmdline_patterns"):
                continue

        for pattern in rule.get("cmdline_patterns", []):
            if re.search(pattern, cmdline, re.IGNORECASE):
                matched = True
                break

        if rule.get("event_ids") and event_id in rule["event_ids"]:
            matched = True

        if matched:
            hits.append(rule)

    return hits


def match_linux_rules(event: dict) -> list:
    cmdline = (event.get("command_line", "") + " " + event.get("message", "")).lower()
    hits = []

    for rule in LINUX_PRIVESC_RULES:
        for pattern in rule.get("cmdline_patterns", []):
            if re.search(pattern, cmdline, re.IGNORECASE):
                hits.append(rule)
                break

    return hits


def run_detection(events: list) -> list:
    alerts = []
    # Track per-user privilege escalation chains
    user_alerts = defaultdict(list)

    for event in events:
        os_type = event.get("os", "windows").lower()
        host = event.get("host", "unknown")
        user = event.get("user", "unknown")
        ts = datetime.fromtimestamp(event.get("ts", 0), tz=timezone.utc).isoformat()

        rules = match_windows_rules(event) if os_type == "windows" else match_linux_rules(event)

        for rule in rules:
            alert = {
                "alert_type": "PRIVILEGE_ESCALATION",
                "severity": rule["severity"],
                "mitre_tactic": "Privilege Escalation",
                "mitre_technique": rule["mitre"],
                "rule_id": rule["id"],
                "rule_name": rule["name"],
                "host": host,
                "user": user,
                "os": os_type,
                "description": rule["description"],
                "command_line": event.get("command_line", "")[:300],
                "process": event.get("process_name", ""),
                "parent_process": event.get("parent_process", ""),
                "event_id": event.get("event_id", ""),
                "event_time": ts,
                "detection_timestamp": datetime.now(timezone.utc).isoformat(),
                "recommended_action": (
                    f"Review process tree on {host} for user {user}. "
                    "Check if escalation succeeded via privilege audit. "
                    "Isolate host if admin-level access confirmed. "
                    "Pull event logs before attacker clears them."
                ),
            }
            alerts.append(alert)
            user_alerts[f"{host}|{user}"].append(rule["id"])

    # Multi-rule chain alert: same user triggering multiple privesc techniques = active attack
    for key, rule_ids in user_alerts.items():
        if len(set(rule_ids)) >= 3:
            host, user = key.split("|", 1)
            alerts.append({
                "alert_type": "PRIVESC_CHAIN_DETECTED",
                "severity": "CRITICAL",
                "mitre_technique": "T1134 / T1548 / T1068",
                "host": host,
                "user": user,
                "rule_ids_triggered": list(set(rule_ids)),
                "description": f"User {user} on {host} triggered {len(set(rule_ids))} privilege escalation rules — active attack campaign",
                "detection_timestamp": datetime.now(timezone.utc).isoformat(),
                "recommended_action": "IMMEDIATE ISOLATION. Active privilege escalation attack in progress.",
            })

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    alerts.sort(key=lambda x: severity_order.get(x.get("severity", "MEDIUM"), 9))
    return alerts


# ── Reporting ─────────────────────────────────────────────────────────────────
def print_report(alerts: list):
    print("\n" + "═" * 70)
    print("  PRIVILEGE ESCALATION DETECTOR — THREAT REPORT")
    print("═" * 70)
    if not alerts:
        print("  ✅ No privilege escalation detected.")
        return

    critical = sum(1 for a in alerts if a.get("severity") == "CRITICAL")
    print(f"  🚨 {len(alerts)} detection(s): {critical} CRITICAL\n")

    for i, a in enumerate(alerts, 1):
        print(f"  [{i}] {a.get('severity')} — {a.get('rule_name', a.get('alert_type'))}")
        print(f"      Host: {a.get('host')} | User: {a.get('user')} | OS: {a.get('os', 'N/A')}")
        print(f"      {a.get('description', '')}")
        if a.get("command_line"):
            print(f"      CMD: {a['command_line'][:80]}...")
        print(f"      MITRE: {a.get('mitre_technique')}")
        print()
    print("═" * 70)


def save_report(alerts: list, output_path: str):
    with open(output_path, "w") as f:
        json.dump({"total_alerts": len(alerts), "alerts": alerts}, f, indent=2)
    print(f"  📄 Report saved → {output_path}")


def main():
    log_path = sys.argv[1] if len(sys.argv) > 1 else "sample_process_events.ndjson"
    output_path = sys.argv[2] if len(sys.argv) > 2 else "privesc_report.json"
    print(f"[*] Loading process events: {log_path}")
    events = parse_process_events(log_path)
    print(f"[*] Events loaded: {len(events)}")
    alerts = run_detection(events)
    print_report(alerts)
    save_report(alerts, output_path)


if __name__ == "__main__":
    main()
