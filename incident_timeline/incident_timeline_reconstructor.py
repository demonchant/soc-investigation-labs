"""
Incident Timeline Reconstructor — Multi-Source Attack Narrative Engine
======================================================================
Correlates events across multiple log sources (auth, network, process,
file, cloud) to reconstruct a coherent attack timeline with:
  - Attack phase detection (Recon → Initial Access → Execution → ...)
  - Host-to-host pivot graph
  - Attacker TTPs mapped to MITRE ATT&CK kill chain
  - Dwell time calculation
  - Automated IR report generation

This is the tool that turns raw log data into an incident report.
It's what you run AFTER the breach to understand what happened,
and it demonstrates the highest level of SOC analytical capability.

MITRE ATT&CK: Full kill chain coverage.

Author: Oladapo Damilola (Wizardskull)
"""

import json
import sys
from collections import defaultdict
from datetime import datetime, timezone


# ── Kill Chain Phases ─────────────────────────────────────────────────────────
KILL_CHAIN_PHASES = [
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

# ── Event Classifiers ─────────────────────────────────────────────────────────
# Maps event patterns → (kill chain phase, MITRE technique, severity)
EVENT_CLASSIFIERS = [
    # Reconnaissance
    {"pattern": {"api_call_contains": ["List", "Describe", "Scan"]},
     "phase": "Reconnaissance", "mitre": "T1580", "severity": "LOW"},
    {"pattern": {"process_contains": "nmap", "cmdline_contains": "-sS"},
     "phase": "Reconnaissance", "mitre": "T1046", "severity": "MEDIUM"},

    # Initial Access
    {"pattern": {"event_type": "auth", "status": "success", "src_external": True},
     "phase": "Initial Access", "mitre": "T1078", "severity": "HIGH"},
    {"pattern": {"process_contains": "mshta.exe", "cmdline_contains": "http"},
     "phase": "Initial Access", "mitre": "T1218.005", "severity": "HIGH"},

    # Execution
    {"pattern": {"process_contains": "powershell.exe", "cmdline_contains": "-enc"},
     "phase": "Execution", "mitre": "T1059.001", "severity": "HIGH"},
    {"pattern": {"process_contains": "cmd.exe", "parent_contains": "winword.exe"},
     "phase": "Execution", "mitre": "T1059.003", "severity": "CRITICAL"},
    {"pattern": {"process_contains": "wmic.exe", "cmdline_contains": "process call create"},
     "phase": "Execution", "mitre": "T1047", "severity": "HIGH"},

    # Persistence
    {"pattern": {"process_contains": "schtasks.exe", "cmdline_contains": "/create"},
     "phase": "Persistence", "mitre": "T1053.005", "severity": "HIGH"},
    {"pattern": {"process_contains": "reg.exe", "cmdline_contains": "run"},
     "phase": "Persistence", "mitre": "T1547.001", "severity": "HIGH"},

    # Privilege Escalation
    {"pattern": {"process_contains": "fodhelper.exe"},
     "phase": "Privilege Escalation", "mitre": "T1548.002", "severity": "CRITICAL"},
    {"pattern": {"api_call_contains": ["VirtualAllocEx", "WriteProcessMemory"]},
     "phase": "Privilege Escalation", "mitre": "T1055", "severity": "CRITICAL"},

    # Defense Evasion
    {"pattern": {"process_contains": "certutil.exe", "cmdline_contains": "-decode"},
     "phase": "Defense Evasion", "mitre": "T1140", "severity": "HIGH"},
    {"pattern": {"event_id": 1102},
     "phase": "Defense Evasion", "mitre": "T1070.001", "severity": "CRITICAL"},
    {"pattern": {"event_id": 104},
     "phase": "Defense Evasion", "mitre": "T1070.001", "severity": "CRITICAL"},

    # Credential Access
    {"pattern": {"process_contains": "ntdsutil.exe"},
     "phase": "Credential Access", "mitre": "T1003.003", "severity": "CRITICAL"},
    {"pattern": {"process_contains": "mimikatz"},
     "phase": "Credential Access", "mitre": "T1003.001", "severity": "CRITICAL"},
    {"pattern": {"event_id": 4769, "cmdline_contains": "RC4"},
     "phase": "Credential Access", "mitre": "T1558.003", "severity": "HIGH"},

    # Discovery
    {"pattern": {"process_contains": "net.exe", "cmdline_contains": "domain admins"},
     "phase": "Discovery", "mitre": "T1087.002", "severity": "MEDIUM"},
    {"pattern": {"process_contains": "nltest.exe", "cmdline_contains": "/dclist"},
     "phase": "Discovery", "mitre": "T1482", "severity": "HIGH"},
    {"pattern": {"process_contains": "ipconfig.exe"},
     "phase": "Discovery", "mitre": "T1016", "severity": "LOW"},

    # Lateral Movement
    {"pattern": {"event_type": "auth", "protocol": "SMB", "src_internal": True},
     "phase": "Lateral Movement", "mitre": "T1021.002", "severity": "HIGH"},
    {"pattern": {"process_contains": "psexec", "src_internal": True},
     "phase": "Lateral Movement", "mitre": "T1021", "severity": "HIGH"},

    # Collection
    {"pattern": {"process_contains": "7z.exe", "cmdline_contains": "\\users\\"},
     "phase": "Collection", "mitre": "T1074.001", "severity": "HIGH"},

    # C2
    {"pattern": {"connection_regularity": "high", "dst_external": True},
     "phase": "Command and Control", "mitre": "T1071.001", "severity": "HIGH"},

    # Exfiltration
    {"pattern": {"dst_domain_contains": ["dropbox.com", "mega.nz", "wetransfer.com"]},
     "phase": "Exfiltration", "mitre": "T1567", "severity": "CRITICAL"},

    # Impact
    {"pattern": {"process_contains": "vssadmin.exe", "cmdline_contains": "delete"},
     "phase": "Impact", "mitre": "T1490", "severity": "CRITICAL"},
    {"pattern": {"file_ext_contains": [".locked", ".encrypted", ".ryuk", ".lockbit"]},
     "phase": "Impact", "mitre": "T1486", "severity": "CRITICAL"},
]

INTERNAL_RANGES = ["10.", "192.168.", "172.16.", "172.17.", "172.18.",
                   "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                   "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                   "172.29.", "172.30.", "172.31."]


def is_internal_ip(ip: str) -> bool:
    return any(ip.startswith(r) for r in INTERNAL_RANGES)


def match_classifier(event: dict, classifier: dict) -> bool:
    """Check if event matches a classifier pattern."""
    pattern = classifier["pattern"]
    proc = event.get("process_name", "").lower()
    cmdline = event.get("command_line", "").lower()
    parent = event.get("parent_process", "").lower()
    api = event.get("api_call", "").lower()
    event_type = event.get("event_type", "")
    status = event.get("status", "")
    protocol = event.get("protocol", "")
    event_id = event.get("event_id")
    src_ip = event.get("src_ip", "")
    dst_host = event.get("dst_host", event.get("domain", ""))
    new_ext = event.get("new_extension", "")

    for key, val in pattern.items():
        if key == "process_contains":
            if val.lower() not in proc:
                return False
        elif key == "cmdline_contains":
            if isinstance(val, list):
                if not any(v.lower() in cmdline for v in val):
                    return False
            elif val.lower() not in cmdline:
                return False
        elif key == "parent_contains":
            if val.lower() not in parent:
                return False
        elif key == "api_call_contains":
            if isinstance(val, list):
                if not any(v.lower() in api for v in val):
                    return False
            elif val.lower() not in api:
                return False
        elif key == "event_type":
            if event_type != val:
                return False
        elif key == "status":
            if status.lower() != val:
                return False
        elif key == "protocol":
            if protocol.upper() != val:
                return False
        elif key == "event_id":
            if event_id != val:
                return False
        elif key == "src_external":
            if val and is_internal_ip(src_ip):
                return False
        elif key == "src_internal":
            if val and not is_internal_ip(src_ip):
                return False
        elif key == "dst_domain_contains":
            if not any(d.lower() in dst_host.lower() for d in val):
                return False
        elif key == "file_ext_contains":
            if not any(e.lower() in new_ext.lower() for e in val):
                return False
        # Note: connection_regularity requires pre-computation, simplified here

    return True


def classify_event(event: dict) -> list:
    """Return all matching classifiers for an event."""
    matches = []
    for clf in EVENT_CLASSIFIERS:
        if match_classifier(event, clf):
            matches.append(clf)
    return matches


def parse_all_logs(log_path: str) -> list:
    """Parse unified multi-source event log."""
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
                ev["ts_human"] = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
                events.append(ev)
            except (json.JSONDecodeError, KeyError, ValueError) as e:
                print(f"[WARN] Line {line_num}: {e}", file=sys.stderr)
    return sorted(events, key=lambda e: e["ts"])


def reconstruct_timeline(events: list) -> dict:
    """Build the full attack timeline from classified events."""
    timeline_events = []
    phase_coverage = defaultdict(int)
    host_pivot_graph = defaultdict(set)
    affected_hosts = set()
    affected_users = set()
    src_ips = set()

    for ev in events:
        classifications = classify_event(ev)
        if not classifications:
            continue

        # Use highest severity classification
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        classifications.sort(key=lambda c: sev_order.get(c["severity"], 9))
        clf = classifications[0]

        host = ev.get("host", ev.get("src_ip", "unknown"))
        user = ev.get("username", ev.get("user", ""))
        src = ev.get("src_ip", "")
        dst = ev.get("dst_ip", ev.get("dst_host", ""))

        affected_hosts.add(host)
        if user:
            affected_users.add(user)
        if src:
            src_ips.add(src)

        # Build host pivot graph
        if src and dst and is_internal_ip(src) and is_internal_ip(dst) and src != dst:
            host_pivot_graph[src].add(dst)

        phase_coverage[clf["phase"]] += 1

        timeline_events.append({
            "ts": ev["ts_human"],
            "phase": clf["phase"],
            "mitre_technique": clf["mitre"],
            "severity": clf["severity"],
            "host": host,
            "user": user,
            "description": _describe_event(ev, clf),
            "raw_event_type": ev.get("event_type", ""),
        })

    return {
        "timeline": timeline_events,
        "phase_coverage": dict(phase_coverage),
        "affected_hosts": list(affected_hosts),
        "affected_users": list(affected_users),
        "external_src_ips": [ip for ip in src_ips if not is_internal_ip(ip)],
        "host_pivot_graph": {k: list(v) for k, v in host_pivot_graph.items()},
    }


def _describe_event(ev: dict, clf: dict) -> str:
    """Generate human-readable event description."""
    proc = ev.get("process_name", "").split("\\")[-1]
    user = ev.get("username", ev.get("user", ""))
    host = ev.get("host", "")
    cmdline = ev.get("command_line", "")[:80]

    base = f"[{clf['phase']}] {clf['mitre']}"
    if proc:
        base += f" — {proc}"
    if user:
        base += f" by {user}"
    if host:
        base += f" on {host}"
    if cmdline:
        base += f" | cmd: {cmdline}"
    return base


def calculate_dwell_time(timeline: list) -> dict:
    """Calculate attacker dwell time from first to last event."""
    if not timeline:
        return {"dwell_seconds": 0, "dwell_human": "N/A"}

    ts_list = [t["ts"] for t in timeline]
    ts_list.sort()

    first = datetime.fromisoformat(ts_list[0].replace("Z", "+00:00"))
    last = datetime.fromisoformat(ts_list[-1].replace("Z", "+00:00"))
    dwell_secs = (last - first).total_seconds()

    if dwell_secs < 3600:
        dwell_human = f"{dwell_secs/60:.0f} minutes"
    elif dwell_secs < 86400:
        dwell_human = f"{dwell_secs/3600:.1f} hours"
    else:
        dwell_human = f"{dwell_secs/86400:.1f} days"

    return {
        "dwell_seconds": round(dwell_secs),
        "dwell_human": dwell_human,
        "first_event": ts_list[0],
        "last_event": ts_list[-1],
    }


def assess_impact(reconstruction: dict) -> dict:
    """Assess overall incident impact."""
    phases = reconstruction["phase_coverage"]
    hosts = len(reconstruction["affected_hosts"])
    users = len(reconstruction["affected_users"])
    pivots = len(reconstruction["host_pivot_graph"])

    impact_score = 0
    impact_indicators = []

    if "Impact" in phases:
        impact_score += 50
        impact_indicators.append("CRITICAL: Ransomware or data destruction detected")

    if "Exfiltration" in phases:
        impact_score += 40
        impact_indicators.append("Data exfiltration detected")

    if "Credential Access" in phases:
        impact_score += 30
        impact_indicators.append("Credential theft — assume all passwords compromised")

    if "Lateral Movement" in phases or pivots > 0:
        impact_score += 20
        impact_indicators.append(f"Lateral movement: {pivots} host(s) pivoted")

    if hosts > 5:
        impact_score += 20
        impact_indicators.append(f"Wide impact: {hosts} hosts affected")

    impact_level = "CRITICAL" if impact_score >= 80 else \
                   "HIGH" if impact_score >= 50 else \
                   "MEDIUM" if impact_score >= 30 else "LOW"

    return {
        "impact_level": impact_level,
        "impact_score": min(impact_score, 100),
        "indicators": impact_indicators,
        "hosts_affected": hosts,
        "users_affected": users,
    }


def generate_report(reconstruction: dict, dwell: dict, impact: dict,
                    incident_id: str) -> dict:
    """Generate full IR report."""
    phases_detected = list(reconstruction["phase_coverage"].keys())

    # Kill chain completeness
    kill_chain_hit = [p for p in KILL_CHAIN_PHASES if p in phases_detected]
    kill_chain_pct = len(kill_chain_hit) / len(KILL_CHAIN_PHASES) * 100

    # Prioritized remediation
    remediation = []
    if "Impact" in phases_detected:
        remediation.append("1. ISOLATE all affected hosts immediately")
        remediation.append("2. Activate incident response retainer")
        remediation.append("3. DO NOT reboot — preserve memory for forensics")
    if "Credential Access" in phases_detected:
        remediation.append("4. Reset ALL passwords enterprise-wide")
        remediation.append("5. Revoke all active sessions and tokens")
        remediation.append("6. Enable MFA on all accounts")
    if "Lateral Movement" in phases_detected:
        remediation.append("7. Audit all hosts in pivot graph for persistence")
    remediation.append("8. Engage forensics team for root cause analysis")
    remediation.append("9. Review and patch initial access vector")
    remediation.append("10. Notify relevant authorities and affected parties per breach law")

    return {
        "incident_id": incident_id,
        "report_generated": datetime.now(timezone.utc).isoformat(),
        "executive_summary": {
            "impact_level": impact["impact_level"],
            "dwell_time": dwell["dwell_human"],
            "hosts_affected": impact["hosts_affected"],
            "users_affected": impact["users_affected"],
            "kill_chain_coverage": f"{kill_chain_pct:.0f}%",
            "phases_observed": phases_detected,
            "external_attacker_ips": reconstruction["external_src_ips"],
        },
        "attack_timeline": reconstruction["timeline"],
        "kill_chain_mapping": {
            "phases_detected": kill_chain_hit,
            "phases_missing": [p for p in KILL_CHAIN_PHASES if p not in phases_detected],
            "coverage_pct": round(kill_chain_pct, 1),
        },
        "host_pivot_graph": reconstruction["host_pivot_graph"],
        "dwell_time": dwell,
        "impact_assessment": impact,
        "remediation_steps": remediation,
        "mitre_techniques_observed": list({e["mitre_technique"]
                                          for e in reconstruction["timeline"]}),
    }


def print_report(report: dict):
    s = report["executive_summary"]
    print("\n" + "═" * 70)
    print(f"  INCIDENT TIMELINE RECONSTRUCTOR — IR REPORT {report['incident_id']}")
    print("═" * 70)
    print(f"  Impact Level:    {s['impact_level']}")
    print(f"  Dwell Time:      {s['dwell_time']}")
    print(f"  Hosts Affected:  {s['hosts_affected']}")
    print(f"  Users Affected:  {s['users_affected']}")
    print(f"  Kill Chain:      {s['kill_chain_coverage']} coverage")
    print(f"  External IPs:    {', '.join(s['external_attacker_ips'][:3]) or 'none'}")
    print()

    print("  ATTACK PHASES OBSERVED:")
    for phase in s["phases_observed"]:
        print(f"  ✅ {phase}")
    print()

    print("  TIMELINE (chronological):")
    for ev in report["attack_timeline"][:15]:
        print(f"  [{ev['ts'][:19]}] {ev['severity']:8s} {ev['phase']}")
        print(f"    {ev['description'][:80]}")
    if len(report["attack_timeline"]) > 15:
        print(f"  ... and {len(report['attack_timeline'])-15} more events (see JSON report)")

    print()
    print("  REMEDIATION PRIORITIES:")
    for step in report["remediation_steps"][:5]:
        print(f"  {step}")
    print("═" * 70)


def main():
    log_path = sys.argv[1] if len(sys.argv) > 1 else "sample_incident_logs.ndjson"
    out_path = sys.argv[2] if len(sys.argv) > 2 else "incident_report.json"

    import hashlib, time
    incident_id = "IR-" + hashlib.md5(str(time.time()).encode()).hexdigest()[:6].upper()

    print(f"[*] Loading incident logs: {log_path}")
    events = parse_all_logs(log_path)
    print(f"[*] Total events: {len(events)}")
    print(f"[*] Incident ID: {incident_id}")

    reconstruction = reconstruct_timeline(events)
    dwell = calculate_dwell_time(reconstruction["timeline"])
    impact = assess_impact(reconstruction)
    report = generate_report(reconstruction, dwell, impact, incident_id)

    print_report(report)

    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"  📄 Full IR report saved → {out_path}")


if __name__ == "__main__":
    main()
