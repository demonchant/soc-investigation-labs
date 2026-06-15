"""
Lateral Movement Tracker — Internal Network Propagation Detector
================================================================
Detects lateral movement by tracking authentication chains between
internal hosts. Builds a directed graph of authentication events and
identifies suspicious propagation patterns like Pass-the-Hash,
Pass-the-Ticket, and remote service exploitation chains.

MITRE ATT&CK:
  T1021     - Remote Services (SMB, WMI, RDP, SSH)
  T1550.002 - Pass the Hash
  T1550.003 - Pass the Ticket
  T1076     - Remote Desktop Protocol
  T1021.006 - Windows Remote Management

Author: Oladapo Damilola (Wizardskull)
"""

import json
import sys
from collections import defaultdict, deque
from datetime import datetime, timezone


# ── Configuration ─────────────────────────────────────────────────────────────
CONFIG = {
    "lateral_window_seconds": 600,       # 10-min window to chain events
    "min_hop_chain_length": 3,           # alert if chain ≥ 3 hops
    "suspicious_protocols": {            # protocols that enable lateral movement
        "SMB", "RDP", "WMI", "PSEXEC", "SSH", "WINRM",
        "DCOM", "VNC", "TELNET", "MSSQL"
    },
    "admin_share_patterns": [            # UNC paths suggesting admin shares
        r"ADMIN$", r"C$", r"IPC$", r"\\.*\\admin",
    ],
    "service_account_patterns": [        # service accounts are high-value
        "svc_", "service_", "_svc", "-svc", "admin", "system",
    ],
    "internal_ranges": [                 # RFC1918 — internal only
        "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
        "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
        "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.",
    ],
    "known_jump_servers": {             # legitimate pivot points
        "10.0.0.1", "10.0.0.5",        # e.g., bastion hosts
    },
}


# ── Utility ───────────────────────────────────────────────────────────────────
def is_internal(ip: str) -> bool:
    return any(ip.startswith(r) for r in CONFIG["internal_ranges"])


def is_service_account(username: str) -> bool:
    low = username.lower()
    return any(pat in low for pat in CONFIG["service_account_patterns"])


def is_suspicious_protocol(protocol: str) -> bool:
    return protocol.upper() in CONFIG["suspicious_protocols"]


# ── Graph Engine ──────────────────────────────────────────────────────────────
class AuthGraph:
    """Directed graph: nodes=hosts, edges=auth events between hosts."""

    def __init__(self):
        self.edges = defaultdict(list)   # src_host → [(dst_host, event)]
        self.nodes = {}                  # host → metadata
        self.events = []

    def add_event(self, event: dict):
        src = event["src_host"]
        dst = event["dst_host"]
        self.events.append(event)
        self.edges[src].append((dst, event))

        for host in (src, dst):
            if host not in self.nodes:
                self.nodes[host] = {
                    "auth_count": 0,
                    "unique_users": set(),
                    "protocols_used": set(),
                    "is_internal": is_internal(host),
                }
            self.nodes[host]["auth_count"] += 1
            self.nodes[host]["unique_users"].add(event.get("username", ""))
            self.nodes[host]["protocols_used"].add(event.get("protocol", ""))

    def find_chains(self) -> list:
        """BFS to find authentication propagation chains."""
        chains = []
        visited_chains = set()

        # Sort events by timestamp
        sorted_events = sorted(self.events, key=lambda e: e["ts"])

        for start_event in sorted_events:
            if not is_suspicious_protocol(start_event.get("protocol", "")):
                continue

            # BFS from this starting event
            queue = deque()
            queue.append({
                "path": [start_event["src_host"]],
                "events": [start_event],
                "last_ts": start_event["ts"],
                "current_host": start_event["dst_host"],
            })

            while queue:
                state = queue.popleft()
                path = state["path"]
                current = state["current_host"]
                last_ts = state["last_ts"]

                # Add current host to path
                full_path = path + [current]

                # Check for chain length threshold
                if len(full_path) >= CONFIG["min_hop_chain_length"]:
                    chain_key = "→".join(full_path)
                    if chain_key not in visited_chains:
                        visited_chains.add(chain_key)
                        chains.append({
                            "chain": full_path,
                            "events": state["events"],
                            "hop_count": len(full_path) - 1,
                            "duration_seconds": last_ts - start_event["ts"],
                        })

                # Prevent infinite loops
                if current in path:
                    continue

                # Expand to next hop within time window
                for next_host, next_event in self.edges.get(current, []):
                    time_delta = next_event["ts"] - last_ts
                    if 0 <= time_delta <= CONFIG["lateral_window_seconds"]:
                        queue.append({
                            "path": full_path,
                            "events": state["events"] + [next_event],
                            "last_ts": next_event["ts"],
                            "current_host": next_host,
                        })

        return chains


# ── Log Parser ────────────────────────────────────────────────────────────────
def parse_auth_log(log_path: str) -> AuthGraph:
    """
    Parse Windows Security / Linux auth log events (NDJSON).
    Expected fields: timestamp, src_host, dst_host, username, protocol,
                     event_id (optional), logon_type (optional), status
    """
    graph = AuthGraph()

    with open(log_path, "r") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                event = json.loads(line)
                src = event["src_host"]
                dst = event["dst_host"]

                if src == dst:  # self-auth, skip
                    continue

                ts_raw = event["timestamp"]
                if isinstance(ts_raw, (int, float)):
                    ts = float(ts_raw)
                else:
                    ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00")).timestamp()

                normalized = {
                    "src_host": src,
                    "dst_host": dst,
                    "username": event.get("username", ""),
                    "protocol": event.get("protocol", "UNKNOWN").upper(),
                    "status": event.get("status", "success").lower(),
                    "logon_type": event.get("logon_type", ""),
                    "event_id": event.get("event_id", ""),
                    "ts": ts,
                    "ts_human": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
                }

                # Only track successful auths for movement (failures = noise)
                if normalized["status"] == "success":
                    graph.add_event(normalized)

            except (json.JSONDecodeError, KeyError, ValueError) as e:
                print(f"[WARN] Line {line_num}: {e}", file=sys.stderr)

    return graph


# ── Detection Engine ──────────────────────────────────────────────────────────
def score_chain(chain: dict) -> dict:
    """Score a movement chain for maliciousness."""
    score = 0
    indicators = []

    # Length bonus
    hops = chain["hop_count"]
    score += min(hops * 15, 45)
    if hops >= 4:
        indicators.append(f"long chain ({hops} hops)")

    # Speed — fast lateral movement = automated
    duration = chain["duration_seconds"]
    if hops > 1 and duration > 0:
        secs_per_hop = duration / hops
        if secs_per_hop < 60:
            score += 20
            indicators.append(f"automated speed ({secs_per_hop:.0f}s/hop)")

    # Service account usage
    users = {e.get("username", "") for e in chain["events"]}
    svc_accounts = [u for u in users if is_service_account(u)]
    if svc_accounts:
        score += 15
        indicators.append(f"service account: {', '.join(svc_accounts[:2])}")

    # Protocol diversity (using multiple protocols = sophisticated attacker)
    protocols = {e.get("protocol", "") for e in chain["events"]}
    if len(protocols) > 2:
        score += 10
        indicators.append(f"multi-protocol: {', '.join(protocols)}")

    # Known jump server — reduce suspicion
    if any(h in CONFIG["known_jump_servers"] for h in chain["chain"]):
        score -= 20
        indicators.append("traverses known jump server (FP reduction)")

    return {"score": min(max(score, 0), 100), "indicators": indicators}


def run_detection(graph: AuthGraph) -> list:
    chains = graph.find_chains()
    alerts = []

    for chain in chains:
        scored = score_chain(chain)
        if scored["score"] < 40:
            continue

        first_event = chain["events"][0]
        last_event = chain["events"][-1]
        users = list({e.get("username", "") for e in chain["events"]})
        protocols = list({e.get("protocol", "") for e in chain["events"]})

        severity = "CRITICAL" if scored["score"] >= 80 else \
                   "HIGH" if scored["score"] >= 60 else "MEDIUM"

        alerts.append({
            "alert_type": "LATERAL_MOVEMENT_CHAIN",
            "severity": severity,
            "mitre_tactic": "Lateral Movement",
            "mitre_technique": "T1021 / T1550.002 / T1550.003",
            "chain": " → ".join(chain["chain"]),
            "hop_count": chain["hop_count"],
            "score": scored["score"],
            "indicators": scored["indicators"],
            "users_involved": users,
            "protocols_used": protocols,
            "start_host": chain["chain"][0],
            "end_host": chain["chain"][-1],
            "first_seen": first_event["ts_human"],
            "last_seen": last_event["ts_human"],
            "duration_seconds": round(chain["duration_seconds"], 1),
            "detection_timestamp": datetime.now(timezone.utc).isoformat(),
            "recommended_action": (
                "Isolate end host immediately. Contain source host. "
                "Dump credentials on all traversed hosts (possible credential harvest). "
                "Review all auth events for involved accounts. "
                "Engage incident response — potential domain compromise."
            ),
        })

    alerts.sort(key=lambda x: x["score"], reverse=True)
    return alerts


# ── Reporting ─────────────────────────────────────────────────────────────────
def print_report(alerts: list, graph: AuthGraph):
    print("\n" + "═" * 70)
    print("  LATERAL MOVEMENT TRACKER — THREAT REPORT")
    print("═" * 70)
    print(f"  Hosts in auth graph: {len(graph.nodes)}")
    print(f"  Total auth events processed: {len(graph.events)}")

    if not alerts:
        print("  ✅ No lateral movement chains detected.")
        return

    print(f"  🚨 {len(alerts)} suspicious movement chain(s)\n")
    for i, a in enumerate(alerts, 1):
        print(f"  [{i}] {a['severity']} — Score: {a['score']}/100")
        print(f"      Chain: {a['chain']}")
        print(f"      Hops: {a['hop_count']} | Duration: {a['duration_seconds']}s")
        print(f"      Users: {', '.join(a['users_involved'][:3])}")
        print(f"      Protocols: {', '.join(a['protocols_used'])}")
        print(f"      Indicators: {' | '.join(a['indicators'])}")
        print(f"      MITRE: {a['mitre_technique']}")
        print()
    print("═" * 70)


def save_report(alerts: list, output_path: str):
    with open(output_path, "w") as f:
        json.dump({"total_alerts": len(alerts), "alerts": alerts}, f, indent=2)
    print(f"  📄 Report saved → {output_path}")


def main():
    log_path = sys.argv[1] if len(sys.argv) > 1 else "sample_auth_events.ndjson"
    output_path = sys.argv[2] if len(sys.argv) > 2 else "lateral_movement_report.json"
    print(f"[*] Loading auth events: {log_path}")
    graph = parse_auth_log(log_path)
    print(f"[*] Auth graph: {len(graph.nodes)} hosts, {len(graph.events)} events")
    alerts = run_detection(graph)
    print_report(alerts, graph)
    save_report(alerts, output_path)


if __name__ == "__main__":
    main()
