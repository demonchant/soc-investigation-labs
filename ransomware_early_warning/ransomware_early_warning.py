"""
Ransomware Early Warning System — Pre-Encryption Activity Detector
==================================================================
Detects ransomware in its early stages — BEFORE encryption completes.
Monitors file system entropy changes, shadow copy deletion, backup
tampering, ransom note creation, and extension modification patterns.

Catching ransomware at stage 1 (recon) or stage 2 (staging) prevents
the catastrophic stage 3 (encryption). This tool is the difference
between a near-miss and a $millions incident.

MITRE ATT&CK:
  T1486  - Data Encrypted for Impact
  T1490  - Inhibit System Recovery (shadow copy deletion)
  T1485  - Data Destruction
  T1083  - File and Directory Discovery (pre-encryption recon)
  T1222  - File and Directory Permissions Modification

Author: Oladapo Damilola (Wizardskull)
"""

import json
import math
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone


CONFIG = {
    "entropy_threshold": 7.2,            # bits; encrypted/compressed files ≈ 7.9
    "file_mod_rate_per_min": 100,        # >100 file mods/min = encryption in progress
    "extension_change_threshold": 20,    # >20 extension changes = ransomware
    "ransom_note_patterns": [            # filenames used by known ransomware families
        r"how_to_decrypt", r"readme\.txt", r"!readme!", r"decrypt_instructions",
        r"your_files_are_encrypted", r"how_to_recover", r"ransom_note",
        r"!!!important!!!", r"_restore_", r"DECRYPT_MY_FILES",
        r"recover_files", r"@wanadecryptor", r"@please_read_me@",
    ],
    "known_ransomware_extensions": {     # extensions added by known ransomware families
        ".locked", ".encrypted", ".enc", ".crypt", ".crypted",
        ".wannacry", ".wcry", ".wncry", ".wncryt",
        ".locky", ".zepto", ".odin", ".thor",
        ".cerber", ".cerber2", ".cerber3",
        ".bit", ".sage", ".globe",
        ".dharma", ".phobos", ".karma",
        ".ryuk", ".ryk",
        ".maze", ".ragnar",
        ".lockbit", ".lckd",
        ".blackcat", ".alphv",
        ".cl0p", ".clop",
    },
    "shadow_copy_commands": [           # VSS deletion patterns
        r"vssadmin.*delete.*shadows",
        r"wmic.*shadowcopy.*delete",
        r"bcdedit.*/set.*recoveryenabled.*no",
        r"bcdedit.*/set.*bootstatuspolicy.*ignoreallfailures",
        r"wbadmin.*delete.*catalog",
        r"schtasks.*/delete.*backup",
        r"diskshadow.*delete.*shadows",
    ],
    "backup_tamper_patterns": [
        r"net.*stop.*backup",
        r"sc.*stop.*vss",
        r"taskkill.*backup",
        r"net.*stop.*\"windows backup\"",
        r"reg.*delete.*backup",
    ],
    "process_kill_patterns": [          # ransomware kills AV/backup processes
        r"taskkill.*/im.*(sqlserver|mysql|oracle|postgres)",
        r"taskkill.*/im.*(mbam|malwarebytes|kaspersky|avast|avg)",
        r"net.*stop.*(mssql|mysql|oracle)",
        r"taskkill.*/im.*backup",
    ],
}

RANSOMWARE_FAMILIES = {
    ".wncry": "WannaCry",
    ".wcry": "WannaCry",
    ".locky": "Locky",
    ".cerber": "Cerber",
    ".dharma": "Dharma",
    ".phobos": "Phobos",
    ".ryuk": "Ryuk",
    ".ryk": "Ryuk",
    ".lockbit": "LockBit",
    ".blackcat": "BlackCat/ALPHV",
    ".cl0p": "Cl0p",
    ".clop": "Cl0p",
}


def calculate_entropy(data_sample: str) -> float:
    """Shannon entropy of file content sample."""
    if not data_sample:
        return 0.0
    freq = defaultdict(int)
    for c in data_sample:
        freq[c] += 1
    total = len(data_sample)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def parse_file_events(log_path: str) -> tuple:
    """
    Parse file system and process events (NDJSON).
    Returns (file_events, process_events)
    """
    file_events = []
    process_events = []

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

                event_type = ev.get("event_type", "file")
                if event_type == "process":
                    process_events.append(ev)
                else:
                    file_events.append(ev)
            except (json.JSONDecodeError, KeyError, ValueError) as e:
                print(f"[WARN] Line {line_num}: {e}", file=sys.stderr)

    return file_events, process_events


def analyze_file_events(file_events: list) -> list:
    alerts = []
    host_tracker = defaultdict(lambda: {
        "modifications": [],
        "extension_changes": [],
        "ransom_notes": [],
        "high_entropy_files": [],
        "renamed_extensions": defaultdict(int),
    })

    for ev in file_events:
        host = ev.get("host", "unknown")
        path = ev.get("file_path", "")
        action = ev.get("action", "").lower()
        new_ext = ev.get("new_extension", "")
        entropy = float(ev.get("entropy", 0))
        ts = ev.get("ts", 0)
        filename = path.split("\\")[-1].split("/")[-1].lower()

        d = host_tracker[host]

        # Track all modifications
        if action in ("write", "modify", "rename", "create"):
            d["modifications"].append(ts)

        # Ransom note detection
        for pattern in CONFIG["ransom_note_patterns"]:
            if re.search(pattern, filename, re.IGNORECASE):
                d["ransom_notes"].append({"path": path, "ts": ts})
                break

        # Extension change to known ransomware extension
        if new_ext and new_ext.lower() in CONFIG["known_ransomware_extensions"]:
            family = RANSOMWARE_FAMILIES.get(new_ext.lower(), "Unknown")
            d["extension_changes"].append({
                "path": path, "new_ext": new_ext, "family": family, "ts": ts
            })
            d["renamed_extensions"][new_ext.lower()] += 1

        # High entropy file (encrypted content)
        if entropy >= CONFIG["entropy_threshold"]:
            d["high_entropy_files"].append({"path": path, "entropy": entropy, "ts": ts})

    # Analyze per host
    for host, d in host_tracker.items():
        indicators = []
        score = 0
        severity = "LOW"

        # File modification rate
        if len(d["modifications"]) >= 10:
            mods = sorted(d["modifications"])
            window = mods[-1] - mods[0]
            rate = (len(mods) / window * 60) if window > 0 else 0
            if rate >= CONFIG["file_mod_rate_per_min"]:
                indicators.append(f"mass file modification: {rate:.0f} files/min")
                score += 40
                severity = "CRITICAL"

        # Ransom notes
        if d["ransom_notes"]:
            indicators.append(f"ransom note created: {d['ransom_notes'][0]['path']}")
            score += 50
            severity = "CRITICAL"

        # Known ransomware extensions
        if len(d["extension_changes"]) >= CONFIG["extension_change_threshold"]:
            family = d["extension_changes"][0].get("family", "Unknown")
            indicators.append(f"ransomware extension changes: {len(d['extension_changes'])} files ({family})")
            score += 45
            severity = "CRITICAL"
        elif d["extension_changes"]:
            indicators.append(f"suspicious extension changes: {len(d['extension_changes'])}")
            score += 20
            severity = "HIGH" if severity != "CRITICAL" else severity

        # High entropy mass files
        if len(d["high_entropy_files"]) >= 10:
            indicators.append(f"high-entropy files: {len(d['high_entropy_files'])} (encryption in progress)")
            score += 35
            severity = "CRITICAL" if score >= 50 else "HIGH"

        if score < 20:
            continue

        families = list({e["family"] for e in d["extension_changes"] if e.get("family")})
        alerts.append({
            "alert_type": "RANSOMWARE_EARLY_WARNING",
            "severity": severity,
            "mitre_technique": "T1486 / T1490",
            "mitre_tactic": "Impact",
            "host": host,
            "ransomware_score": min(score, 100),
            "identified_families": families,
            "indicators": indicators,
            "file_modifications": len(d["modifications"]),
            "ransom_notes_found": len(d["ransom_notes"]),
            "encrypted_extensions": len(d["extension_changes"]),
            "high_entropy_files": len(d["high_entropy_files"]),
            "detection_timestamp": datetime.now(timezone.utc).isoformat(),
            "recommended_action": (
                f"IMMEDIATE ISOLATION of {host}. "
                "Disconnect from network — do NOT shut down (memory forensics). "
                "Notify IR team and management immediately. "
                "DO NOT pay ransom before consulting IR. "
                "Identify patient zero — check lateral movement logs. "
                "Restore from offline backup after full environment clean."
            ),
        })

    return alerts


def analyze_process_events(process_events: list) -> list:
    alerts = []
    host_signals = defaultdict(list)

    for ev in process_events:
        cmdline = ev.get("command_line", "")
        host = ev.get("host", "unknown")

        for pattern in CONFIG["shadow_copy_commands"]:
            if re.search(pattern, cmdline, re.IGNORECASE):
                host_signals[host].append(("shadow_copy_deletion", pattern, ev))
                break

        for pattern in CONFIG["backup_tamper_patterns"]:
            if re.search(pattern, cmdline, re.IGNORECASE):
                host_signals[host].append(("backup_tampering", pattern, ev))
                break

        for pattern in CONFIG["process_kill_patterns"]:
            if re.search(pattern, cmdline, re.IGNORECASE):
                host_signals[host].append(("process_kill", pattern, ev))
                break

    for host, signals in host_signals.items():
        if not signals:
            continue
        sig_types = [s[0] for s in signals]
        severity = "CRITICAL" if "shadow_copy_deletion" in sig_types else "HIGH"

        alerts.append({
            "alert_type": "RANSOMWARE_PRE_ENCRYPTION",
            "severity": severity,
            "mitre_technique": "T1490" if "shadow_copy_deletion" in sig_types else "T1486",
            "mitre_tactic": "Impact",
            "host": host,
            "signals": [{"type": s[0], "command": s[2].get("command_line","")[:100]} for s in signals],
            "signal_count": len(signals),
            "description": f"Pre-encryption behavior on {host}: {', '.join(set(sig_types))}",
            "detection_timestamp": datetime.now(timezone.utc).isoformat(),
            "recommended_action": (
                "Shadow copy deletion detected — ransomware preparation in progress. "
                "ISOLATE HOST IMMEDIATELY. Preserve memory dump. "
                "Check all hosts for same patterns — likely lateral spread."
            ),
        })

    return alerts


def run_detection(file_events: list, process_events: list) -> list:
    alerts = analyze_file_events(file_events) + analyze_process_events(process_events)
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    alerts.sort(key=lambda x: sev_order.get(x.get("severity","LOW"), 9))
    return alerts


def print_report(alerts: list):
    print("\n" + "═" * 70)
    print("  RANSOMWARE EARLY WARNING SYSTEM — THREAT REPORT")
    print("═" * 70)
    if not alerts:
        print("  ✅ No ransomware indicators detected.")
        return
    critical = sum(1 for a in alerts if a["severity"] == "CRITICAL")
    print(f"  🚨 {len(alerts)} alert(s): {critical} CRITICAL\n")
    for i, a in enumerate(alerts, 1):
        print(f"  [{i}] {a['severity']} — {a['alert_type']} | {a['host']}")
        if "indicators" in a:
            for ind in a["indicators"]:
                print(f"      ⚠ {ind}")
        if "description" in a:
            print(f"      {a['description']}")
        if a.get("identified_families"):
            print(f"      Ransomware family: {', '.join(a['identified_families'])}")
        print(f"      MITRE: {a['mitre_technique']}")
        print()
    print("═" * 70)


def save_report(alerts, path):
    with open(path, "w") as f:
        json.dump({"total_alerts": len(alerts), "alerts": alerts}, f, indent=2)
    print(f"  📄 Report saved → {path}")


def main():
    log_path = sys.argv[1] if len(sys.argv) > 1 else "sample_filesystem.ndjson"
    out_path = sys.argv[2] if len(sys.argv) > 2 else "ransomware_report.json"
    print(f"[*] Loading file system log: {log_path}")
    file_events, process_events = parse_file_events(log_path)
    print(f"[*] File events: {len(file_events)} | Process events: {len(process_events)}")
    alerts = run_detection(file_events, process_events)
    print_report(alerts)
    save_report(alerts, out_path)


if __name__ == "__main__":
    main()
