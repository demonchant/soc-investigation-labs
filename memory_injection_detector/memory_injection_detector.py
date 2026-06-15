"""
Memory Injection Indicator Detector — Process Hollowing & DLL Injection Analyzer
=================================================================================
Detects in-memory attack techniques that leave minimal disk footprint:
  - Process hollowing (unmapped executables in memory)
  - DLL injection patterns (unusual DLL loads from non-standard paths)
  - Reflective DLL loading indicators
  - Shell code injection signals
  - Parent PID spoofing correlated with memory anomalies
  - Suspicious memory allocation API usage patterns

MITRE ATT&CK:
  T1055     - Process Injection
  T1055.001 - DLL Injection
  T1055.002 - Portable Executable Injection
  T1055.004 - Asynchronous Procedure Call
  T1055.012 - Process Hollowing
  T1620     - Reflective Code Loading

Author: Oladapo Damilola (Wizardskull)
"""

import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone


CONFIG = {
    "suspicious_dll_paths": [
        r"\\temp\\", r"\\tmp\\", r"\\appdata\\local\\temp\\",
        r"\\users\\public\\", r"\\programdata\\",
        r"\\windows\\tasks\\", r"\\recycle",
        r"/tmp/", r"/dev/shm/", r"/var/tmp/",
    ],
    "injection_apis": {
        # Windows API calls used for injection (from EDR/API monitoring)
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "NtCreateThreadEx", "RtlCreateUserThread",
        "QueueUserAPC", "NtQueueApcThread",
        "SetWindowsHookEx", "SetThreadContext",
        "NtMapViewOfSection", "MapViewOfFile2",
        "LoadLibraryA", "LoadLibraryW",
        "NtWriteVirtualMemory", "NtAllocateVirtualMemory",
        "VirtualProtect",  # marking shellcode as executable
    },
    "hollowing_api_sequence": [
        # Classic process hollowing sequence
        ["CreateProcess", "NtUnmapViewOfSection", "VirtualAllocEx",
         "WriteProcessMemory", "SetThreadContext", "ResumeThread"],
        # Alternative hollowing
        ["CreateProcessInternalW", "ZwUnmapViewOfSection",
         "VirtualAllocEx", "WriteProcessMemory"],
    ],
    "suspicious_memory_permissions": [
        "PAGE_EXECUTE_READWRITE",  # RWX — shellcode staging
        "PAGE_EXECUTE_WRITECOPY",
    ],
    "known_clean_dll_paths": [
        r"c:\\windows\\system32\\",
        r"c:\\windows\\syswow64\\",
        r"c:\\program files\\",
        r"c:\\program files (x86)\\",
        r"/usr/lib/", r"/lib/", r"/usr/local/lib/",
    ],
    "reflective_load_indicators": [
        r"ReflectiveDllInjection",
        r"ReflectiveLoader",
        r"#reflect",         # export name used by meterpreter
        r"memdump",
        r"shellcode",
        r"sc\.bin",
        r"beacon\.bin",      # Cobalt Strike beacon artifact
        r"inject\.(exe|dll|bin)",
    ],
}


def parse_edr_log(log_path: str) -> list:
    """
    Parse EDR/API monitoring logs (NDJSON).
    Expected: timestamp, host, process_name, pid, ppid, api_call,
              target_process (optional), dll_path (optional),
              memory_permissions (optional), file_path (optional)
    """
    events = []
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
                events.append(ev)
            except (json.JSONDecodeError, KeyError, ValueError) as e:
                print(f"[WARN] Line {line_num}: {e}", file=sys.stderr)
    return events


def detect_dll_injection(events: list) -> list:
    """Detect DLL injection via unusual load paths and API sequences."""
    alerts = []
    process_dll_loads = defaultdict(list)

    for ev in events:
        api = ev.get("api_call", "")
        dll_path = ev.get("dll_path", "").lower()
        if not dll_path:
            continue

        if "LoadLibrary" in api or api in ("LdrLoadDll", "NtMapViewOfSection"):
            # Check if DLL loaded from suspicious path
            is_clean = any(dll_path.startswith(p.lower()) for p in CONFIG["known_clean_dll_paths"])
            is_suspicious = any(pat.lower() in dll_path for pat in CONFIG["suspicious_dll_paths"])

            if is_suspicious or (not is_clean and dll_path):
                pid = ev.get("pid", "")
                process = ev.get("process_name", "")
                key = f"{ev.get('host','')}|{process}|{pid}"
                process_dll_loads[key].append({
                    "dll_path": dll_path, "api": api, "ts": ev["ts"],
                    "host": ev.get("host", ""), "process": process, "pid": pid,
                    "user": ev.get("user", ""),
                })

    for key, loads in process_dll_loads.items():
        host, process, pid = key.split("|")
        alerts.append({
            "alert_type": "DLL_INJECTION_DETECTED",
            "severity": "HIGH",
            "mitre_technique": "T1055.001",
            "mitre_tactic": "Defense Evasion / Privilege Escalation",
            "host": host,
            "process": process,
            "pid": pid,
            "suspicious_dll_loads": len(loads),
            "dll_paths": [l["dll_path"] for l in loads[:5]],
            "event_time": datetime.fromtimestamp(loads[0]["ts"], tz=timezone.utc).isoformat(),
        })

    return alerts


def detect_process_hollowing(events: list) -> list:
    """Detect process hollowing via API sequence analysis."""
    alerts = []
    pid_api_sequences = defaultdict(list)

    for ev in events:
        api = ev.get("api_call", "")
        pid = str(ev.get("pid", ""))
        host = ev.get("host", "unknown")
        if api in CONFIG["injection_apis"]:
            pid_api_sequences[f"{host}|{pid}"].append({
                "api": api, "ts": ev["ts"],
                "host": host, "pid": pid,
                "process": ev.get("process_name", ""),
                "target": ev.get("target_process", ""),
                "mem_perm": ev.get("memory_permissions", ""),
            })

    for key, calls in pid_api_sequences.items():
        host, pid = key.split("|", 1)
        apis_seen = [c["api"] for c in calls]
        apis_set = set(apis_seen)

        # Check for hollowing sequence
        hollowing_score = 0
        hollowing_indicators = []

        if "CreateRemoteThread" in apis_set or "NtCreateThreadEx" in apis_set:
            hollowing_score += 30
            hollowing_indicators.append("remote thread creation")

        if "VirtualAllocEx" in apis_set and "WriteProcessMemory" in apis_set:
            hollowing_score += 35
            hollowing_indicators.append("remote memory allocation + write")

        if "NtUnmapViewOfSection" in apis_set or "ZwUnmapViewOfSection" in apis_set:
            hollowing_score += 25
            hollowing_indicators.append("section unmapping (hollowing)")

        if any(c.get("mem_perm") in CONFIG["suspicious_memory_permissions"] for c in calls):
            hollowing_score += 20
            hollowing_indicators.append("RWX memory permissions (shellcode staging)")

        if hollowing_score < 30:
            continue

        target_procs = list({c["target"] for c in calls if c.get("target")})
        severity = "CRITICAL" if hollowing_score >= 60 else "HIGH"

        alerts.append({
            "alert_type": "PROCESS_HOLLOWING_DETECTED",
            "severity": severity,
            "mitre_technique": "T1055.012",
            "mitre_tactic": "Defense Evasion",
            "host": host,
            "pid": pid,
            "process": calls[0].get("process", "unknown"),
            "target_processes": target_procs,
            "hollowing_score": min(hollowing_score, 100),
            "api_sequence": apis_seen[:10],
            "indicators": hollowing_indicators,
            "event_time": datetime.fromtimestamp(calls[0]["ts"], tz=timezone.utc).isoformat(),
        })

    return alerts


def detect_reflective_loading(events: list) -> list:
    """Detect reflective DLL loading via file/command indicators."""
    alerts = []
    for ev in events:
        cmdline = ev.get("command_line", "")
        file_path = ev.get("file_path", ev.get("dll_path", ""))
        combined = (cmdline + " " + file_path).lower()

        for pattern in CONFIG["reflective_load_indicators"]:
            if re.search(pattern, combined, re.IGNORECASE):
                alerts.append({
                    "alert_type": "REFLECTIVE_CODE_LOADING",
                    "severity": "CRITICAL",
                    "mitre_technique": "T1620",
                    "mitre_tactic": "Defense Evasion",
                    "host": ev.get("host", "unknown"),
                    "process": ev.get("process_name", ""),
                    "matched_pattern": pattern,
                    "command_line": cmdline[:200],
                    "file_path": file_path,
                    "event_time": datetime.fromtimestamp(ev["ts"], tz=timezone.utc).isoformat(),
                })
                break
    return alerts


def detect_cross_process_access(events: list) -> list:
    """Detect one process injecting into another (OpenProcess + WriteProcessMemory)."""
    alerts = []
    host_cross = defaultdict(list)

    for ev in events:
        api = ev.get("api_call", "")
        target = ev.get("target_process", "")
        process = ev.get("process_name", "")
        host = ev.get("host", "")

        if api in ("OpenProcess", "NtOpenProcess") and target and target != process:
            # Accessing another process
            if target.lower() in ("lsass.exe", "winlogon.exe", "csrss.exe",
                                   "services.exe", "svchost.exe"):
                host_cross[host].append({
                    "api": api, "attacker": process, "target": target,
                    "ts": ev["ts"], "host": host,
                })

    for host, accesses in host_cross.items():
        if len(accesses) >= 2:
            targets = list({a["target"] for a in accesses})
            alerts.append({
                "alert_type": "CROSS_PROCESS_INJECTION",
                "severity": "CRITICAL",
                "mitre_technique": "T1055",
                "mitre_tactic": "Defense Evasion / Privilege Escalation",
                "host": host,
                "processes_targeted": targets,
                "access_count": len(accesses),
                "attackers": list({a["attacker"] for a in accesses}),
                "description": f"Process(es) opening handles to {', '.join(targets)} — credential access or injection",
                "event_time": datetime.fromtimestamp(accesses[0]["ts"], tz=timezone.utc).isoformat(),
            })

    return alerts


def run_detection(events: list) -> list:
    alerts = []
    alerts.extend(detect_dll_injection(events))
    alerts.extend(detect_process_hollowing(events))
    alerts.extend(detect_reflective_loading(events))
    alerts.extend(detect_cross_process_access(events))

    now = datetime.now(timezone.utc).isoformat()
    for a in alerts:
        a["detection_timestamp"] = now
        a["recommended_action"] = (
            f"Capture memory dump of host '{a.get('host', 'unknown')}' IMMEDIATELY. "
            "Do NOT reboot — memory evidence will be lost. "
            "Isolate host from network. "
            "Submit memory dump for forensic analysis. "
            "Check parent process chain for initial compromise vector."
        )

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    alerts.sort(key=lambda x: sev_order.get(x.get("severity", "MEDIUM"), 9))
    return alerts


def print_report(alerts: list):
    print("\n" + "═" * 70)
    print("  MEMORY INJECTION DETECTOR — THREAT REPORT")
    print("═" * 70)
    if not alerts:
        print("  ✅ No memory injection indicators detected.")
        return
    critical = sum(1 for a in alerts if a["severity"] == "CRITICAL")
    print(f"  🚨 {len(alerts)} injection indicator(s): {critical} CRITICAL\n")
    for i, a in enumerate(alerts, 1):
        print(f"  [{i}] {a['severity']} — {a['alert_type']}")
        print(f"      Host: {a.get('host')} | Process: {a.get('process', 'N/A')}")
        if "indicators" in a:
            for ind in a["indicators"]:
                print(f"      ⚠ {ind}")
        if "description" in a:
            print(f"      {a['description']}")
        print(f"      MITRE: {a.get('mitre_technique')}")
        print()
    print("═" * 70)


def save_report(alerts, path):
    with open(path, "w") as f:
        json.dump({"total_alerts": len(alerts), "alerts": alerts}, f, indent=2)
    print(f"  📄 Report saved → {path}")


def main():
    log_path = sys.argv[1] if len(sys.argv) > 1 else "sample_edr_events.ndjson"
    out_path = sys.argv[2] if len(sys.argv) > 2 else "memory_injection_report.json"
    print(f"[*] Loading EDR events: {log_path}")
    events = parse_edr_log(log_path)
    print(f"[*] EDR events: {len(events)}")
    alerts = run_detection(events)
    print_report(alerts)
    save_report(alerts, out_path)


if __name__ == "__main__":
    main()
