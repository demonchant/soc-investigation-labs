"""
Threat Hunt Framework — Hypothesis-Driven Hunt Orchestrator
============================================================
A production-grade threat hunting framework that operationalizes the
PEAK (Prepare, Execute, Act, Knowledge) hunting methodology.

Runs structured hunt hypotheses against log data, tracks evidence,
scores hunt confidence, and produces actionable hunt reports.

This is the meta-tool — it orchestrates the other detection modules
and provides a structured way to document, run, and report hunts.

MITRE ATT&CK: Full framework coverage via configurable hypotheses.

Author: Oladapo Damilola (Wizardskull)
Role Target: SOC L2/L3 | Threat Hunter | Detection Engineer
"""

import json
import sys
import hashlib
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Callable


# ── Hunt Hypothesis Framework ─────────────────────────────────────────────────
class HuntHypothesis:
    """
    A structured threat hunting hypothesis.
    Follows: PEAK methodology — Prepare, Execute, Act, Knowledge.
    """
    def __init__(self, hunt_id: str, title: str, description: str,
                 mitre_technique: str, mitre_tactic: str,
                 data_sources: list, ioc_types: list, hunt_fn: Callable):
        self.hunt_id = hunt_id
        self.title = title
        self.description = description
        self.mitre_technique = mitre_technique
        self.mitre_tactic = mitre_tactic
        self.data_sources = data_sources   # what logs are needed
        self.ioc_types = ioc_types         # what IOC types this produces
        self.hunt_fn = hunt_fn             # detection function
        self.status = "PENDING"
        self.findings = []
        self.evidence = []
        self.start_time = None
        self.end_time = None
        self.confidence = 0                # 0-100
        self.verdict = "UNCONFIRMED"       # CONFIRMED / UNCONFIRMED / FP

    def execute(self, data: dict) -> dict:
        self.start_time = time.time()
        self.status = "RUNNING"
        try:
            result = self.hunt_fn(data)
            self.findings = result.get("findings", [])
            self.evidence = result.get("evidence", [])
            self.confidence = result.get("confidence", 0)
            self.verdict = "CONFIRMED" if self.confidence >= 70 else \
                          "POSSIBLE" if self.confidence >= 40 else "UNCONFIRMED"
            self.status = "COMPLETED"
        except Exception as e:
            self.status = "ERROR"
            self.findings = [{"error": str(e)}]
        finally:
            self.end_time = time.time()
        return self.to_dict()

    def to_dict(self) -> dict:
        return {
            "hunt_id": self.hunt_id,
            "title": self.title,
            "description": self.description,
            "mitre_technique": self.mitre_technique,
            "mitre_tactic": self.mitre_tactic,
            "data_sources": self.data_sources,
            "status": self.status,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "findings_count": len(self.findings),
            "findings": self.findings[:10],  # top 10
            "evidence_summary": self.evidence[:5],
            "duration_seconds": round(self.end_time - self.start_time, 3) if self.end_time else 0,
        }


# ── Built-in Hunt Functions ───────────────────────────────────────────────────
def hunt_high_entropy_processes(data: dict) -> dict:
    """
    HUNT-001: Detect processes with high-entropy names (random names = malware).
    Malware like Emotet, TrickBot, Dridex use random executable names.
    """
    import math, string

    def char_entropy(s: str) -> float:
        s = s.lower()
        freq = defaultdict(int)
        for c in s:
            if c in string.ascii_lowercase + string.digits:
                freq[c] += 1
        total = sum(freq.values())
        if total < 3:
            return 0.0
        return -sum((c / total) * math.log2(c / total) for c in freq.values())

    # Known legitimate random-looking but valid processes
    known_legit = {
        "svchost.exe", "dllhost.exe", "conhost.exe", "wuauclt.exe",
        "msmpeng.exe", "mpcmdrun.exe", "searchindexer.exe",
    }

    findings = []
    processes = data.get("processes", [])

    for proc in processes:
        name = proc.get("process_name", "").split("\\")[-1].lower()
        stem = name.replace(".exe", "").replace(".dll", "")

        if name in known_legit or len(stem) < 5:
            continue

        entropy = char_entropy(stem)
        # High entropy + unusual path = suspicious
        path = proc.get("process_path", "").lower()
        in_temp = any(p in path for p in ["\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\", "\\downloads\\"])

        if entropy >= 3.8 or (entropy >= 3.2 and in_temp):
            findings.append({
                "process": name,
                "path": proc.get("process_path", ""),
                "host": proc.get("host", ""),
                "user": proc.get("user", ""),
                "entropy": round(entropy, 4),
                "in_temp_path": in_temp,
                "risk": "HIGH" if entropy >= 3.8 else "MEDIUM",
            })

    confidence = min(len(findings) * 15, 90) if findings else 0
    return {
        "findings": findings,
        "evidence": [f"Found {len(findings)} high-entropy process names"],
        "confidence": confidence,
    }


def hunt_parent_process_spoofing(data: dict) -> dict:
    """
    HUNT-002: Detect parent process spoofing (PPID spoofing).
    Attackers spawn processes with fake parents to evade behavioral detection.
    Common indicator: cmd.exe spawned by WMI, or powershell spawned by Excel.
    """
    SUSPICIOUS_PARENT_CHILD = {
        "winword.exe": ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"],
        "excel.exe":   ["cmd.exe", "powershell.exe", "wscript.exe"],
        "outlook.exe": ["cmd.exe", "powershell.exe"],
        "acrobat.exe": ["cmd.exe", "powershell.exe"],
        "chrome.exe":  ["cmd.exe", "powershell.exe", "mshta.exe"],
        "iexplore.exe":["cmd.exe", "powershell.exe", "mshta.exe", "cscript.exe"],
        "wmiprvse.exe":["powershell.exe", "cmd.exe"],  # WMI spawning shells
        "mmc.exe":     ["powershell.exe", "cmd.exe"],
    }

    findings = []
    processes = data.get("processes", [])

    for proc in processes:
        child = proc.get("process_name", "").split("\\")[-1].lower()
        parent = proc.get("parent_process", "").split("\\")[-1].lower()

        for suspicious_parent, suspicious_children in SUSPICIOUS_PARENT_CHILD.items():
            if parent == suspicious_parent and child in suspicious_children:
                findings.append({
                    "host": proc.get("host", ""),
                    "user": proc.get("user", ""),
                    "parent": parent,
                    "child": child,
                    "command_line": proc.get("command_line", "")[:200],
                    "verdict": f"Office/browser spawning shell — possible macro or exploit",
                })

    confidence = min(len(findings) * 25, 95) if findings else 0
    return {
        "findings": findings,
        "evidence": [f"{len(findings)} suspicious parent-child process relationships"],
        "confidence": confidence,
    }


def hunt_network_port_anomalies(data: dict) -> dict:
    """
    HUNT-003: Detect unusual port/protocol combinations suggesting C2 or exfil.
    """
    STANDARD_PORT_MAP = {
        80: "HTTP", 443: "HTTPS", 53: "DNS", 25: "SMTP",
        587: "SMTP", 993: "IMAPS", 995: "POP3S", 22: "SSH",
        3389: "RDP", 445: "SMB", 135: "RPC", 139: "NetBIOS",
    }
    SUSPICIOUS_PORTS = {4444, 4445, 1234, 9999, 31337, 5555, 8888, 7777,
                        2222, 3333, 6666, 1337, 8443, 9001, 9030}  # Tor defaults

    findings = []
    connections = data.get("connections", [])

    for conn in connections:
        dst_port = conn.get("dst_port", 0)
        protocol = conn.get("protocol", "").upper()
        dst_ip = conn.get("dst_ip", "")

        anomalies = []

        # Non-standard port with high traffic
        if dst_port not in STANDARD_PORT_MAP and dst_port not in SUSPICIOUS_PORTS:
            if conn.get("bytes_total", 0) > 1_000_000:  # >1MB on unusual port
                anomalies.append(f"high volume ({conn.get('bytes_total', 0)/1000:.0f}KB) on unusual port {dst_port}")

        if dst_port in SUSPICIOUS_PORTS:
            anomalies.append(f"known attacker port {dst_port}")

        # DNS on non-53 port
        if dst_port != 53 and "DNS" in protocol:
            anomalies.append("DNS traffic on non-standard port")

        # HTTP on non-80/8080 port
        if "HTTP" in protocol and dst_port not in {80, 8080, 8000, 3000}:
            anomalies.append(f"HTTP on unusual port {dst_port}")

        if anomalies:
            findings.append({
                "src_ip": conn.get("src_ip", ""),
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": protocol,
                "anomalies": anomalies,
            })

    confidence = min(len(findings) * 20, 85) if findings else 0
    return {
        "findings": findings,
        "evidence": [f"{len(findings)} port/protocol anomalies"],
        "confidence": confidence,
    }


def hunt_scheduled_task_persistence(data: dict) -> dict:
    """
    HUNT-004: Hunt for scheduled tasks created for persistence.
    Focuses on tasks created outside business hours or by unusual users.
    """
    findings = []
    tasks = data.get("scheduled_tasks", [])
    processes = data.get("processes", [])

    # Look for schtasks.exe in process events
    for proc in processes:
        name = proc.get("process_name", "").split("\\")[-1].lower()
        cmdline = proc.get("command_line", "").lower()
        if name == "schtasks.exe" and "/create" in cmdline:
            # Off-hours check (0-6 AM or after 10 PM)
            ts = proc.get("ts", 0)
            if ts:
                hour = datetime.fromtimestamp(ts, tz=timezone.utc).hour
                off_hours = hour < 6 or hour >= 22
            else:
                off_hours = False

            suspicious = (
                "powershell" in cmdline or
                "cmd.exe" in cmdline or
                "/sc minute" in cmdline or
                "http" in cmdline or
                off_hours
            )
            if suspicious:
                findings.append({
                    "host": proc.get("host", ""),
                    "user": proc.get("user", ""),
                    "command": cmdline[:200],
                    "off_hours": off_hours,
                    "indicators": ["off-hours" if off_hours else "",
                                   "suspicious payload" if "powershell" in cmdline else ""],
                })

    for task in tasks:
        action = task.get("action", "").lower()
        author = task.get("author", "").lower()
        if any(p in action for p in ["powershell", "cmd", "wscript", "mshta"]):
            if "microsoft" not in author and "system" not in author:
                findings.append({
                    "task_name": task.get("name", ""),
                    "action": action[:200],
                    "author": author,
                    "indicators": ["non-system task with shell payload"],
                })

    confidence = min(len(findings) * 30, 90) if findings else 0
    return {
        "findings": findings,
        "evidence": [f"{len(findings)} suspicious scheduled task events"],
        "confidence": confidence,
    }


def hunt_data_staging(data: dict) -> dict:
    """
    HUNT-005: Detect data staging before exfiltration.
    Attackers compress and stage data in predictable locations.
    """
    STAGING_PATHS = [
        r"\\users\\public\\", r"\\programdata\\", r"\\windows\\temp\\",
        r"\\appdata\\local\\temp\\", r"/tmp/", r"/dev/shm/", r"/var/tmp/",
    ]
    ARCHIVE_TOOLS = ["7z.exe", "winrar.exe", "rar.exe", "zip.exe", "tar", "gzip"]
    LARGE_FILE_THRESHOLD_MB = 50

    findings = []
    processes = data.get("processes", [])
    file_events = data.get("file_events", [])

    # Archive tool usage in staging paths
    for proc in processes:
        name = proc.get("process_name", "").split("\\")[-1].lower()
        cmdline = proc.get("command_line", "").lower()
        path = proc.get("process_path", "").lower()

        if name in ARCHIVE_TOOLS:
            for staging in STAGING_PATHS:
                if staging.lower() in cmdline or staging.lower() in path:
                    findings.append({
                        "host": proc.get("host", ""),
                        "user": proc.get("user", ""),
                        "tool": name,
                        "command": cmdline[:200],
                        "staging_path": staging,
                        "type": "ARCHIVE_IN_STAGING_DIR",
                    })
                    break

    # Large file creation in staging paths
    for fe in file_events:
        size_mb = fe.get("file_size_bytes", 0) / 1_000_000
        file_path = fe.get("file_path", "").lower()
        if size_mb >= LARGE_FILE_THRESHOLD_MB:
            for staging in STAGING_PATHS:
                if staging.lower() in file_path:
                    findings.append({
                        "host": fe.get("host", ""),
                        "user": fe.get("user", ""),
                        "file_path": fe.get("file_path", ""),
                        "size_mb": round(size_mb, 1),
                        "type": "LARGE_FILE_IN_STAGING_DIR",
                    })
                    break

    confidence = min(len(findings) * 25, 90) if findings else 0
    return {
        "findings": findings,
        "evidence": [f"{len(findings)} data staging indicators"],
        "confidence": confidence,
    }


# ── Hunt Campaign Builder ─────────────────────────────────────────────────────
def build_hunt_campaign(campaign_name: str, target_scope: str) -> list:
    """Build the full hunt campaign with all hypotheses."""
    return [
        HuntHypothesis(
            "HUNT-001",
            "High-Entropy Process Name Detection",
            "Malware commonly uses random process names to blend in. "
            "Hunt for executables with high character entropy in temp/user directories.",
            "T1036.005", "Defense Evasion",
            ["process_creation_logs", "EDR_telemetry"],
            ["process_name", "file_hash", "host"],
            hunt_high_entropy_processes,
        ),
        HuntHypothesis(
            "HUNT-002",
            "Parent Process Spoofing / Unusual Spawn Chain",
            "Office apps and browsers should never spawn command shells directly. "
            "This hunts for macro execution, exploits, and PPID spoofing.",
            "T1055", "Defense Evasion / Privilege Escalation",
            ["process_creation_logs", "sysmon_event_1"],
            ["process_chain", "parent_pid", "host"],
            hunt_parent_process_spoofing,
        ),
        HuntHypothesis(
            "HUNT-003",
            "Non-Standard Port / Protocol Anomaly",
            "C2 traffic and exfiltration often uses unexpected ports. "
            "Hunt for traffic on attacker-tooling ports and protocol mismatches.",
            "T1571", "Command and Control",
            ["firewall_logs", "netflow", "proxy_logs"],
            ["ip", "port", "bytes_transferred"],
            hunt_network_port_anomalies,
        ),
        HuntHypothesis(
            "HUNT-004",
            "Suspicious Scheduled Task Persistence",
            "Attackers use scheduled tasks for persistence after initial access. "
            "Hunt for tasks created off-hours or with shell payloads.",
            "T1053.005", "Persistence / Execution",
            ["process_creation_logs", "windows_event_4698"],
            ["task_name", "action", "user", "host"],
            hunt_scheduled_task_persistence,
        ),
        HuntHypothesis(
            "HUNT-005",
            "Pre-Exfiltration Data Staging",
            "Before exfiltrating, attackers stage and compress data in world-writable paths. "
            "Hunt for large archive creation in temp/public directories.",
            "T1074.001", "Collection",
            ["process_creation_logs", "file_creation_logs"],
            ["file_path", "size_bytes", "archive_tool", "host"],
            hunt_data_staging,
        ),
    ]


# ── Hunt Runner ───────────────────────────────────────────────────────────────
class ThreatHuntOrchestrator:
    def __init__(self, campaign_name: str, analyst: str, scope: str):
        self.campaign_name = campaign_name
        self.analyst = analyst
        self.scope = scope
        self.campaign_id = hashlib.md5(
            f"{campaign_name}{time.time()}".encode()
        ).hexdigest()[:8].upper()
        self.start_time = datetime.now(timezone.utc)
        self.hypotheses = build_hunt_campaign(campaign_name, scope)
        self.results = []

    def load_data(self, data_path: str) -> dict:
        """Load hunt data from NDJSON file — organizes by event type."""
        data = defaultdict(list)
        with open(data_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    event = json.loads(line)
                    event_type = event.get("event_type", "processes")
                    ts_raw = event.get("timestamp", 0)
                    if isinstance(ts_raw, str):
                        ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00")).timestamp()
                    else:
                        ts = float(ts_raw)
                    event["ts"] = ts
                    data[event_type].append(event)
                except Exception:
                    pass
        return dict(data)

    def run_all_hunts(self, data: dict) -> list:
        print(f"\n[*] Running {len(self.hypotheses)} hunt hypotheses...")
        for hypothesis in self.hypotheses:
            print(f"    → {hypothesis.hunt_id}: {hypothesis.title}", end="", flush=True)
            result = hypothesis.execute(data)
            self.results.append(result)
            verdict_icon = "🔴" if result["verdict"] == "CONFIRMED" else \
                          "🟡" if result["verdict"] == "POSSIBLE" else "🟢"
            print(f" {verdict_icon} [{result['verdict']}] ({result['confidence']}%)")
        return self.results

    def generate_report(self) -> dict:
        confirmed = [r for r in self.results if r["verdict"] == "CONFIRMED"]
        possible = [r for r in self.results if r["verdict"] == "POSSIBLE"]
        total_findings = sum(r["findings_count"] for r in self.results)

        report = {
            "campaign_id": self.campaign_id,
            "campaign_name": self.campaign_name,
            "analyst": self.analyst,
            "scope": self.scope,
            "hunt_start": self.start_time.isoformat(),
            "hunt_end": datetime.now(timezone.utc).isoformat(),
            "methodology": "PEAK (Prepare, Execute, Act, Knowledge)",
            "summary": {
                "total_hypotheses": len(self.results),
                "confirmed_threats": len(confirmed),
                "possible_threats": len(possible),
                "total_findings": total_findings,
                "overall_verdict": "THREAT_CONFIRMED" if confirmed else
                                   "INVESTIGATE_FURTHER" if possible else "ENVIRONMENT_CLEAR",
            },
            "hunt_results": self.results,
            "recommendations": self._build_recommendations(confirmed, possible),
            "next_hunt_hypotheses": [
                "Hunt for DCSync attacks (T1003.006) if lateral movement confirmed",
                "Hunt for Golden Ticket usage (T1558.001) if Kerberos anomalies found",
                "Hunt for cloud exfiltration (T1567) if staging indicators confirmed",
            ],
        }
        return report

    def _build_recommendations(self, confirmed: list, possible: list) -> list:
        recs = []
        if confirmed:
            recs.append({
                "priority": "IMMEDIATE",
                "action": f"Escalate to IR: {len(confirmed)} confirmed threat(s) found",
                "details": [r["hunt_id"] for r in confirmed],
            })
        if possible:
            recs.append({
                "priority": "HIGH",
                "action": "Collect additional data and extend hunt window for unconfirmed hypotheses",
                "details": [r["hunt_id"] for r in possible],
            })
        recs.append({
            "priority": "MEDIUM",
            "action": "Convert confirmed findings into detection rules for continuous monitoring",
        })
        recs.append({
            "priority": "LOW",
            "action": "Document hunt methodology and add to hunt playbook library",
        })
        return recs

    def print_executive_summary(self, report: dict):
        print("\n" + "═" * 70)
        print(f"  THREAT HUNT REPORT — Campaign {report['campaign_id']}")
        print("═" * 70)
        s = report["summary"]
        print(f"  Campaign: {report['campaign_name']}")
        print(f"  Analyst:  {report['analyst']}")
        print(f"  Scope:    {report['scope']}")
        print(f"  Method:   {report['methodology']}")
        print()
        print(f"  Overall Verdict: {s['overall_verdict']}")
        print(f"  Hypotheses run: {s['total_hypotheses']} | Findings: {s['total_findings']}")
        print(f"  Confirmed: {s['confirmed_threats']} 🔴 | Possible: {s['possible_threats']} 🟡")
        print()
        print("  PRIORITY RECOMMENDATIONS:")
        for rec in report["recommendations"]:
            print(f"  [{rec['priority']}] {rec['action']}")
        print("═" * 70)


# ── Entry Point ───────────────────────────────────────────────────────────────
def main():
    data_path = sys.argv[1] if len(sys.argv) > 1 else "sample_hunt_data.ndjson"
    output_path = sys.argv[2] if len(sys.argv) > 2 else "hunt_report.json"

    orchestrator = ThreatHuntOrchestrator(
        campaign_name="Hunt-001: Suspected APT Intrusion Investigation",
        analyst="Oladapo Damilola (SOC L2)",
        scope="All endpoints and network infrastructure — 2024-01-15 to 2024-01-16",
    )

    print(f"[*] Loading hunt data: {data_path}")
    data = orchestrator.load_data(data_path)
    print(f"[*] Event types loaded: {list(data.keys())}")
    print(f"[*] Total events: {sum(len(v) for v in data.values())}")

    results = orchestrator.run_all_hunts(data)
    report = orchestrator.generate_report()

    orchestrator.print_executive_summary(report)

    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"  📄 Full hunt report saved → {output_path}")


if __name__ == "__main__":
    main()
