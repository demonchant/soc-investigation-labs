"""
Network Reconnaissance Detector — Port Scan & Subnet Sweep Analyzer
====================================================================
Detects network reconnaissance: port scans, subnet sweeps, OS fingerprinting,
service enumeration, and stealth scan techniques (SYN, FIN, NULL, XMAS).
Maps to attack lifecycle stage 1 — catching recon early stops the full attack.

MITRE ATT&CK:
  T1046  - Network Service Discovery
  T1595  - Active Scanning
  T1595.001 - Scanning IP Blocks
  T1595.002 - Vulnerability Scanning
  T1018  - Remote System Discovery

Author: Oladapo Damilola (Wizardskull)
"""

import json
import statistics
import sys
from collections import defaultdict
from datetime import datetime, timezone


CONFIG = {
    "scan_window_seconds": 60,
    "port_scan_threshold": 15,          # >15 unique ports from one src = scan
    "subnet_sweep_threshold": 10,       # >10 unique dst IPs from one src = sweep
    "stealth_scan_flags": {             # TCP flag combinations indicating stealth
        "SYN": "half-open scan",
        "FIN": "FIN scan",
        "NULL": "NULL scan",
        "XMAS": "XMAS scan (FIN+PSH+URG)",
        "ACK": "ACK scan (firewall mapping)",
    },
    "vuln_scanner_ports": {             # ports exclusively probed by scanners
        9390, 9391,   # OpenVAS
        8080, 8443,   # web scanners
        2375, 2376,   # Docker API
        6379,         # Redis (unauthenticated)
        27017,        # MongoDB
        9200, 9300,   # Elasticsearch
        5601,         # Kibana
        4848,         # GlassFish admin
        7001, 7002,   # WebLogic
        8161,         # ActiveMQ
        11211,        # Memcached
        50070,        # Hadoop NameNode
        2181,         # ZooKeeper
    },
    "os_fingerprint_ports": {22, 23, 135, 139, 445, 3389},
    "scan_rate_threshold": 50,          # >50 connections/sec = automated scanner
    "known_scanners": {                 # legit internal scanners (reduce FPs)
        "10.0.0.1", "10.0.0.5",
    },
}

KNOWN_VULN_SCANNERS_UAS = [
    "nmap", "masscan", "zmap", "nessus", "openvas", "qualys",
    "rapid7", "shodan", "censys", "nuclei",
]


def parse_netflow_log(log_path: str) -> list:
    """
    Parse network flow/firewall logs (NDJSON).
    Expected: timestamp, src_ip, dst_ip, dst_port, protocol,
              tcp_flags (optional), user_agent (optional),
              bytes (optional), connection_state
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


def detect_port_scan(events: list) -> list:
    """Detect horizontal port scans from single source."""
    alerts = []
    src_tracker = defaultdict(lambda: {
        "ports": set(), "dst_ips": set(), "timestamps": [],
        "tcp_flags": defaultdict(int), "bytes": [],
        "rejected": 0, "accepted": 0,
    })

    for ev in events:
        src = ev.get("src_ip", "")
        dst = ev.get("dst_ip", "")
        port = ev.get("dst_port", 0)
        flags = ev.get("tcp_flags", "").upper()
        state = ev.get("connection_state", "").upper()
        ts = ev.get("ts", 0)

        d = src_tracker[src]
        d["ports"].add(port)
        d["dst_ips"].add(dst)
        d["timestamps"].append(ts)
        if flags:
            d["tcp_flags"][flags] += 1
        if ev.get("bytes"):
            d["bytes"].append(ev["bytes"])
        if state in ("REJ", "RST", "RSTO", "S0"):
            d["rejected"] += 1
        elif state in ("SF", "S1", "ESTABLISHED"):
            d["accepted"] += 1

    for src, d in src_tracker.items():
        if src in CONFIG["known_scanners"]:
            continue

        unique_ports = len(d["ports"])
        unique_ips = len(d["dst_ips"])

        if unique_ports < CONFIG["port_scan_threshold"] and \
           unique_ips < CONFIG["subnet_sweep_threshold"]:
            continue

        indicators = []
        severity = "MEDIUM"
        score = 0

        # Port scan
        if unique_ports >= CONFIG["port_scan_threshold"]:
            indicators.append(f"port scan: {unique_ports} unique ports probed")
            score += 40
            severity = "HIGH"

        # Subnet sweep
        if unique_ips >= CONFIG["subnet_sweep_threshold"]:
            indicators.append(f"subnet sweep: {unique_ips} unique IPs targeted")
            score += 35
            severity = "HIGH"

        # Stealth scan flags
        for flag, description in CONFIG["stealth_scan_flags"].items():
            if d["tcp_flags"].get(flag, 0) >= 5:
                indicators.append(f"stealth scan: {description} ({d['tcp_flags'][flag]} packets)")
                score += 20
                severity = "CRITICAL"
                break

        # High rejection rate = hitting closed ports
        total = d["rejected"] + d["accepted"]
        if total > 0 and d["rejected"] / total > 0.80:
            indicators.append(f"high rejection rate: {d['rejected']/total:.0%} of connections refused")
            score += 15

        # Scan rate
        if len(d["timestamps"]) >= 5:
            ts_sorted = sorted(d["timestamps"])
            window = ts_sorted[-1] - ts_sorted[0]
            rate = len(d["timestamps"]) / window if window > 0 else 0
            if rate >= CONFIG["scan_rate_threshold"]:
                indicators.append(f"automated scan rate: {rate:.0f} connections/sec")
                score += 20
                if severity != "CRITICAL":
                    severity = "HIGH"

        # Vuln scanner ports
        vuln_ports = d["ports"] & CONFIG["vuln_scanner_ports"]
        if len(vuln_ports) >= 3:
            indicators.append(f"vulnerability scanner ports: {sorted(vuln_ports)[:5]}")
            score += 15

        # OS fingerprinting
        os_ports = d["ports"] & CONFIG["os_fingerprint_ports"]
        if len(os_ports) >= 3:
            indicators.append(f"OS fingerprinting: probing {sorted(os_ports)}")
            score += 10

        if score < 30:
            continue

        alerts.append({
            "alert_type": "NETWORK_RECONNAISSANCE",
            "severity": severity,
            "mitre_technique": "T1046 / T1595",
            "mitre_tactic": "Discovery / Reconnaissance",
            "src_ip": src,
            "recon_score": min(score, 100),
            "unique_ports_probed": unique_ports,
            "unique_ips_targeted": unique_ips,
            "indicators": indicators,
            "total_connections": len(d["timestamps"]),
            "rejected_connections": d["rejected"],
            "sample_ports": sorted(d["ports"])[:20],
            "tcp_flags_seen": dict(d["tcp_flags"]),
            "detection_timestamp": datetime.now(timezone.utc).isoformat(),
            "recommended_action": (
                f"Block {src} at perimeter firewall immediately. "
                "Check if src IP is internal (compromised host) or external (attacker). "
                "If internal: isolate host and check for malware. "
                "If external: add to threat intel blocklist. "
                "Review what services were successfully reached (accepted connections)."
            ),
        })

    alerts.sort(key=lambda x: x["recon_score"], reverse=True)
    return alerts


def run_detection(events: list) -> list:
    return detect_port_scan(events)


def print_report(alerts: list):
    print("\n" + "═" * 70)
    print("  NETWORK RECONNAISSANCE DETECTOR — THREAT REPORT")
    print("═" * 70)
    if not alerts:
        print("  ✅ No reconnaissance activity detected.")
        return
    print(f"  🚨 {len(alerts)} scanning source(s)\n")
    for i, a in enumerate(alerts, 1):
        print(f"  [{i}] {a['severity']} — Score: {a['recon_score']}/100 | {a['src_ip']}")
        print(f"      Ports: {a['unique_ports_probed']} | IPs: {a['unique_ips_targeted']} | Connections: {a['total_connections']}")
        for ind in a["indicators"]:
            print(f"      ⚠ {ind}")
        print(f"      Sample ports: {a['sample_ports'][:10]}")
        print(f"      MITRE: {a['mitre_technique']}")
        print()
    print("═" * 70)


def save_report(alerts, path):
    with open(path, "w") as f:
        json.dump({"total_alerts": len(alerts), "alerts": alerts}, f, indent=2)
    print(f"  📄 Report saved → {path}")


def main():
    log_path = sys.argv[1] if len(sys.argv) > 1 else "sample_netflow.ndjson"
    out_path = sys.argv[2] if len(sys.argv) > 2 else "recon_report.json"
    print(f"[*] Loading netflow log: {log_path}")
    events = parse_netflow_log(log_path)
    print(f"[*] Network events: {len(events)}")
    alerts = run_detection(events)
    print_report(alerts)
    save_report(alerts, out_path)


if __name__ == "__main__":
    main()
