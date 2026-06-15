"""
LOLBas Detector — Living-off-the-Land Binary & Script Attack Detector
======================================================================
Detects abuse of legitimate Windows/Linux system binaries to execute
malicious payloads — a core attacker technique to evade signature-based
detection. Maps detections to LOLBAS project and MITRE ATT&CK.

MITRE ATT&CK:
  T1218     - System Binary Proxy Execution
  T1059     - Command and Scripting Interpreter
  T1036.003 - Masquerading: Rename System Utilities
  T1140     - Deobfuscate/Decode Files or Information
  T1197     - BITS Jobs

Author: Oladapo Damilola (Wizardskull)
"""

import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone


# ── LOLBas Rule Engine ────────────────────────────────────────────────────────
# Each rule: binary name, suspicious argument patterns, MITRE ID, description
LOLBAS_RULES = {
    # ── Proxy Execution ──────────────────────────────────────────────────────
    "mshta.exe": {
        "patterns": [r"http[s]?://", r"vbscript:", r"javascript:", r"\.hta"],
        "mitre": "T1218.005",
        "tactic": "Defense Evasion",
        "description": "MSHTA executing remote or script content — common malware dropper technique",
        "severity": "HIGH",
    },
    "regsvr32.exe": {
        "patterns": [r"/s\s+/u\s+/i:http", r"scrobj\.dll", r"http[s]?://", r"/i:http"],
        "mitre": "T1218.010",
        "tactic": "Defense Evasion",
        "description": "Regsvr32 Squiblydoo — proxy execution via COM scriptlets",
        "severity": "CRITICAL",
    },
    "rundll32.exe": {
        "patterns": [r"javascript:", r"shell32\.dll.*shellexec", r"url\.dll.*openurl",
                     r"http[s]?://", r"\.dll,#\d+"],
        "mitre": "T1218.011",
        "tactic": "Defense Evasion",
        "description": "Rundll32 proxy execution — executing DLLs or remote scripts",
        "severity": "HIGH",
    },
    "certutil.exe": {
        "patterns": [r"-urlcache", r"-decode", r"-encode", r"http[s]?://", r"-f\s+http"],
        "mitre": "T1140",
        "tactic": "Defense Evasion",
        "description": "Certutil file download or base64 decode — classic malware staging",
        "severity": "HIGH",
    },
    "bitsadmin.exe": {
        "patterns": [r"/transfer", r"/create", r"/addfile.*http", r"http[s]?://"],
        "mitre": "T1197",
        "tactic": "Defense Evasion / Persistence",
        "description": "BITS job abuse for stealthy file download or persistence",
        "severity": "HIGH",
    },
    "wmic.exe": {
        "patterns": [r"process call create", r"os get.*/format:http", r"http[s]?://",
                     r"shadowcopy delete", r"xsl\s+http"],
        "mitre": "T1218.009",
        "tactic": "Execution / Defense Evasion",
        "description": "WMIC remote process creation or XSL script execution",
        "severity": "CRITICAL",
    },
    "cscript.exe": {
        "patterns": [r"\.vbs", r"\.js\b", r"http[s]?://", r"wscript\.shell",
                     r"powershell", r"cmd\.exe"],
        "mitre": "T1059.005",
        "tactic": "Execution",
        "description": "CScript/WScript executing suspicious scripts",
        "severity": "HIGH",
    },
    "wscript.exe": {
        "patterns": [r"\.vbs", r"\.js\b", r"http[s]?://", r"wscript\.shell"],
        "mitre": "T1059.005",
        "tactic": "Execution",
        "description": "WScript executing suspicious script content",
        "severity": "HIGH",
    },

    # ── PowerShell Abuse ──────────────────────────────────────────────────────
    "powershell.exe": {
        "patterns": [r"-enc\s+[A-Za-z0-9+/=]{20,}", r"-encodedcommand",
                     r"iex\s*\(", r"invoke-expression", r"downloadstring",
                     r"bypass.*-exec", r"-nop.*-w.*hidden", r"frombase64string",
                     r"webclient", r"net\.webclient"],
        "mitre": "T1059.001",
        "tactic": "Execution",
        "description": "PowerShell encoded/obfuscated execution — common in fileless attacks",
        "severity": "CRITICAL",
    },
    "pwsh.exe": {  # PowerShell Core
        "patterns": [r"-enc\s+[A-Za-z0-9+/=]{20,}", r"iex\s*\(",
                     r"downloadstring", r"invoke-expression"],
        "mitre": "T1059.001",
        "tactic": "Execution",
        "description": "PowerShell Core suspicious execution",
        "severity": "HIGH",
    },

    # ── Credential Access ─────────────────────────────────────────────────────
    "ntdsutil.exe": {
        "patterns": [r"ifm", r"create full", r"ac i ntds", r"snapshot"],
        "mitre": "T1003.003",
        "tactic": "Credential Access",
        "description": "NTDS.dit extraction via ntdsutil — credential dumping",
        "severity": "CRITICAL",
    },
    "procdump.exe": {
        "patterns": [r"lsass", r"-ma\s+\d+", r"-accepteula.*lsass"],
        "mitre": "T1003.001",
        "tactic": "Credential Access",
        "description": "Procdump targeting LSASS — credential dump attempt",
        "severity": "CRITICAL",
    },
    "vssadmin.exe": {
        "patterns": [r"delete\s+shadows", r"resize\s+shadowstorage", r"list\s+shadows"],
        "mitre": "T1490",
        "tactic": "Impact",
        "description": "VSS shadow copy deletion — ransomware anti-recovery technique",
        "severity": "CRITICAL",
    },

    # ── Discovery / Recon ─────────────────────────────────────────────────────
    "net.exe": {
        "patterns": [r"user.*\/domain", r"group.*\"domain admins\"", r"localgroup.*administrators",
                     r"accounts.*\/domain", r"share"],
        "mitre": "T1087.002",
        "tactic": "Discovery",
        "description": "Net.exe domain enumeration — attacker recon of AD structure",
        "severity": "MEDIUM",
    },
    "nltest.exe": {
        "patterns": [r"\/dclist", r"\/domain_trusts", r"\/trusted_domains", r"\/server"],
        "mitre": "T1482",
        "tactic": "Discovery",
        "description": "Nltest domain trust enumeration — mapping AD trust relationships",
        "severity": "HIGH",
    },

    # ── Persistence ───────────────────────────────────────────────────────────
    "schtasks.exe": {
        "patterns": [r"/create.*http", r"/tr.*powershell", r"/tr.*cmd.*\/c",
                     r"/sc\s+minute", r"/ru\s+system"],
        "mitre": "T1053.005",
        "tactic": "Persistence / Execution",
        "description": "Scheduled task creation with suspicious payload",
        "severity": "HIGH",
    },
    "reg.exe": {
        "patterns": [r"add.*run\b", r"add.*runonce", r"export.*sam", r"export.*system",
                     r"save.*hklm\\sam"],
        "mitre": "T1547.001",
        "tactic": "Persistence / Credential Access",
        "description": "Registry Run key persistence or SAM hive export",
        "severity": "HIGH",
    },

    # ── Linux LOLBins ─────────────────────────────────────────────────────────
    "wget": {
        "patterns": [r"-O\s+/tmp/", r"-O\s+/dev/shm/", r"\|\s*bash", r"\|\s*sh"],
        "mitre": "T1059.004",
        "tactic": "Execution",
        "description": "Wget download piped to shell — classic Linux dropper",
        "severity": "HIGH",
    },
    "curl": {
        "patterns": [r"\|\s*bash", r"\|\s*sh", r"-o\s+/tmp/", r"-o\s+/dev/shm/",
                     r"--output\s+/tmp/"],
        "mitre": "T1059.004",
        "tactic": "Execution",
        "description": "Curl download piped to shell execution",
        "severity": "HIGH",
    },
    "python": {
        "patterns": [r"-c.*import.*socket", r"-c.*exec\(", r"-c.*__import__",
                     r"http\.server", r"SimpleHTTPServer"],
        "mitre": "T1059.006",
        "tactic": "Execution / Command and Control",
        "description": "Python one-liner execution — reverse shells or HTTP servers",
        "severity": "HIGH",
    },
    "python3": {
        "patterns": [r"-c.*import.*socket", r"-c.*exec\(", r"-c.*__import__",
                     r"http\.server"],
        "mitre": "T1059.006",
        "tactic": "Execution",
        "description": "Python3 suspicious one-liner",
        "severity": "HIGH",
    },
    "bash": {
        "patterns": [r"-i.*>&.*/dev/tcp/", r"0>&1", r"exec.*bash.*>&.*tcp",
                     r"/dev/tcp/.*\/.*\|"],
        "mitre": "T1059.004",
        "tactic": "Execution",
        "description": "Bash reverse shell pattern — /dev/tcp redirection",
        "severity": "CRITICAL",
    },
    "nc": {
        "patterns": [r"-e\s+/bin/bash", r"-e\s+/bin/sh", r"-lvp", r"-l.*-p"],
        "mitre": "T1059.004",
        "tactic": "Command and Control",
        "description": "Netcat reverse or bind shell",
        "severity": "CRITICAL",
    },
}


# ── Log Parser ────────────────────────────────────────────────────────────────
def parse_process_log(log_path: str) -> list:
    """
    Parse process creation events (NDJSON).
    Expected: timestamp, host, user, process_name, command_line,
              pid, parent_process (optional), event_id (optional)
    """
    events = []
    with open(log_path, "r") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                event = json.loads(line)
                ts_raw = event["timestamp"]
                ts = float(ts_raw) if isinstance(ts_raw, (int, float)) else \
                    datetime.fromisoformat(ts_raw.replace("Z", "+00:00")).timestamp()
                event["ts"] = ts
                events.append(event)
            except (json.JSONDecodeError, KeyError, ValueError) as e:
                print(f"[WARN] Line {line_num}: {e}", file=sys.stderr)
    return events


# ── Detection Engine ──────────────────────────────────────────────────────────
def match_lolbas(event: dict) -> list:
    """Check a process event against all LOLBas rules."""
    proc = event.get("process_name", "").lower().split("\\")[-1]  # strip path
    cmdline = event.get("command_line", "").lower()
    hits = []

    rule = LOLBAS_RULES.get(proc)
    if not rule:
        return hits

    matched_patterns = []
    for pattern in rule["patterns"]:
        if re.search(pattern, cmdline, re.IGNORECASE):
            matched_patterns.append(pattern)

    if matched_patterns:
        hits.append({
            "binary": proc,
            "rule": rule,
            "matched_patterns": matched_patterns,
            "command_line": event.get("command_line", ""),
        })

    return hits


def run_detection(events: list) -> list:
    alerts = []
    # Also track per-host LOLBas usage for burst detection
    host_lolbas = defaultdict(list)

    for event in events:
        hits = match_lolbas(event)
        for hit in hits:
            rule = hit["rule"]
            host = event.get("host", "unknown")
            user = event.get("user", "unknown")
            ts = datetime.fromtimestamp(event["ts"], tz=timezone.utc).isoformat()

            host_lolbas[host].append(hit["binary"])

            alert = {
                "alert_type": "LOLBAS_EXECUTION",
                "severity": rule["severity"],
                "mitre_tactic": rule["tactic"],
                "mitre_technique": rule["mitre"],
                "host": host,
                "user": user,
                "binary": hit["binary"],
                "description": rule["description"],
                "command_line": hit["command_line"][:300],
                "matched_patterns": hit["matched_patterns"],
                "pid": event.get("pid", ""),
                "parent_process": event.get("parent_process", ""),
                "event_id": event.get("event_id", ""),
                "event_time": ts,
                "detection_timestamp": datetime.now(timezone.utc).isoformat(),
                "recommended_action": (
                    f"Review full process tree on {host}. "
                    f"Check parent process of {hit['binary']}. "
                    "Isolate if network connections present. "
                    "Preserve memory for forensics."
                ),
            }
            alerts.append(alert)

    # Burst alert: host using many different LOLBas = active attack campaign
    for host, binaries in host_lolbas.items():
        unique_bins = set(binaries)
        if len(unique_bins) >= 4:
            alerts.append({
                "alert_type": "LOLBAS_CAMPAIGN_BURST",
                "severity": "CRITICAL",
                "mitre_tactic": "Multiple",
                "mitre_technique": "T1218 / T1059 / T1003",
                "host": host,
                "unique_lolbas_used": list(unique_bins),
                "count": len(unique_bins),
                "description": f"Host {host} used {len(unique_bins)} LOLBas tools — likely active attack campaign",
                "detection_timestamp": datetime.now(timezone.utc).isoformat(),
                "recommended_action": "IMMEDIATE ISOLATION. Full memory acquisition. Incident response escalation.",
            })

    # Sort: CRITICAL first, then by time
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    alerts.sort(key=lambda x: severity_order.get(x["severity"], 9))
    return alerts


# ── Reporting ─────────────────────────────────────────────────────────────────
def print_report(alerts: list):
    print("\n" + "═" * 70)
    print("  LOLBas DETECTOR — LIVING-OFF-THE-LAND THREAT REPORT")
    print("═" * 70)
    if not alerts:
        print("  ✅ No LOLBas abuse detected.")
        return

    critical = sum(1 for a in alerts if a["severity"] == "CRITICAL")
    high = sum(1 for a in alerts if a["severity"] == "HIGH")
    print(f"  🚨 {len(alerts)} detection(s): {critical} CRITICAL, {high} HIGH\n")

    for i, a in enumerate(alerts, 1):
        print(f"  [{i}] {a['severity']} — {a['alert_type']}")
        print(f"      Host: {a.get('host', 'N/A')} | User: {a.get('user', 'N/A')}")
        if "binary" in a:
            print(f"      Binary: {a['binary']} | MITRE: {a['mitre_technique']}")
            print(f"      Command: {a.get('command_line', '')[:80]}...")
        if "unique_lolbas_used" in a:
            print(f"      LOLBas used: {', '.join(a['unique_lolbas_used'])}")
        print(f"      {a.get('description', '')}")
        print()
    print("═" * 70)


def save_report(alerts: list, output_path: str):
    with open(output_path, "w") as f:
        json.dump({"total_alerts": len(alerts), "alerts": alerts}, f, indent=2)
    print(f"  📄 Report saved → {output_path}")


def main():
    log_path = sys.argv[1] if len(sys.argv) > 1 else "sample_process_events.ndjson"
    output_path = sys.argv[2] if len(sys.argv) > 2 else "lolbas_report.json"
    print(f"[*] Loading process events: {log_path}")
    events = parse_process_log(log_path)
    print(f"[*] Events loaded: {len(events)}")
    alerts = run_detection(events)
    print_report(alerts)
    save_report(alerts, output_path)


if __name__ == "__main__":
    main()
