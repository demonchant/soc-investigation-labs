"""
C2 Framework Fingerprinter — Jitter Pattern & Signature Analyzer
================================================================
Goes beyond generic beaconing detection to FINGERPRINT which specific
C2 framework is in use (Cobalt Strike, Metasploit, Havoc, Sliver, etc.)
by analysing their distinctive jitter patterns, user-agent signatures,
URI patterns, and timing characteristics.

This is threat intelligence-grade detection — helps IR teams understand
WHAT they're dealing with before remediation.

MITRE ATT&CK:
  T1071.001 - Web Protocols (HTTP/HTTPS C2)
  T1573     - Encrypted Channel
  T1001.002 - Data Obfuscation: Steganography
  T1008     - Fallback Channels

Author: Oladapo Damilola (Wizardskull)
"""

import json
import math
import re
import statistics
import sys
from collections import defaultdict
from datetime import datetime, timezone


# ── C2 Framework Fingerprint Database ────────────────────────────────────────
# Each framework has distinctive characteristics across multiple dimensions
C2_SIGNATURES = {
    "Cobalt Strike": {
        "beacon_intervals_sec": [60],      # default malleable 60s (configurable)
        "jitter_pct_range": (0.0, 0.30),   # 0-30% jitter typical
        "default_ua_patterns": [
            r"Mozilla/4\.0.*MSIE 7\.0",
            r"Mozilla/5\.0.*Windows NT 6\.1.*WOW64.*rv:55\.0",
            r"Mozilla/5\.0.*Macintosh.*Intel Mac OS X.*AppleWebKit",
        ],
        "uri_patterns": [
            r"/__utm\.gif",
            r"/ca$",
            r"/pixel\.gif",
            r"/ptj$",
            r"/updates\.rss",
        ],
        "http_methods": ["GET", "POST"],
        "body_sizes": (0, 1024),
        "ssl_cert_patterns": [r"Major Cobalt", r"TIRETRACKING"],
        "confidence_boost_ua": 20,
        "confidence_boost_uri": 25,
        "mitre_sw": "S0154",
    },
    "Metasploit Meterpreter": {
        "beacon_intervals_sec": [5, 10, 15],  # aggressive check-in
        "jitter_pct_range": (0.0, 0.10),
        "default_ua_patterns": [
            r"Mozilla/4\.0.*compatible; MSIE 6\.0",
            r"^$",  # no user agent
        ],
        "uri_patterns": [
            r"/[A-Za-z0-9]{4,8}$",  # random short URIs
            r"/TarterSauce",
            r"/kBkkAAAAAAAA",
        ],
        "http_methods": ["GET", "POST"],
        "body_sizes": (0, 512),
        "confidence_boost_ua": 15,
        "confidence_boost_uri": 15,
        "mitre_sw": "S0040",
    },
    "Havoc C2": {
        "beacon_intervals_sec": [2, 5],    # very aggressive
        "jitter_pct_range": (0.0, 0.50),
        "default_ua_patterns": [
            r"Mozilla/5\.0.*Windows NT 10\.0.*Win64.*x64.*rv:9[0-9]",
        ],
        "uri_patterns": [
            r"/auth/microsoft",
            r"/i/[A-Za-z0-9]{16}",
        ],
        "http_methods": ["POST"],
        "body_sizes": (100, 4096),
        "confidence_boost_ua": 25,
        "confidence_boost_uri": 20,
        "mitre_sw": None,  # emerging
    },
    "Sliver C2": {
        "beacon_intervals_sec": [60, 120, 300],
        "jitter_pct_range": (0.0, 0.15),
        "default_ua_patterns": [
            r"Mozilla/5\.0.*Linux.*x86_64.*Chrome/\d+",
        ],
        "uri_patterns": [
            r"/[a-z]{4,8}\.js$",
            r"/fonts/[a-f0-9]{8}\.woff",
            r"/assets/",
        ],
        "http_methods": ["GET", "POST"],
        "body_sizes": (50, 2048),
        "confidence_boost_ua": 10,
        "confidence_boost_uri": 15,
        "mitre_sw": None,
    },
    "Brute Ratel C4": {
        "beacon_intervals_sec": [30, 60],
        "jitter_pct_range": (0.0, 0.20),
        "default_ua_patterns": [
            r"Mozilla/5\.0.*Windows NT 10\.0.*Win64.*x64.*Edg/",
        ],
        "uri_patterns": [
            r"/wordpress/wp-login\.php",
            r"/api/v[0-9]/",
        ],
        "http_methods": ["POST"],
        "body_sizes": (200, 4096),
        "confidence_boost_ua": 20,
        "confidence_boost_uri": 20,
        "mitre_sw": "S1063",
    },
    "Covenant": {
        "beacon_intervals_sec": [5, 10],
        "jitter_pct_range": (0.0, 0.10),
        "default_ua_patterns": [
            r"Mozilla/5\.0.*Windows NT 10\.0.*Trident/7\.0",
        ],
        "uri_patterns": [
            r"/en-us/index\.html",
            r"/favicon\.ico",
            r"/css/style\.css",
        ],
        "http_methods": ["GET", "POST"],
        "body_sizes": (0, 512),
        "confidence_boost_ua": 15,
        "confidence_boost_uri": 15,
        "mitre_sw": None,
    },
}


# ── Statistical Utilities ─────────────────────────────────────────────────────
def compute_jitter_pct(intervals: list) -> float:
    """Compute actual jitter as std/mean."""
    if len(intervals) < 3:
        return 0.0
    mean = statistics.mean(intervals)
    return statistics.stdev(intervals) / mean if mean > 0 else 0.0


def interval_regularity(intervals: list) -> float:
    """0.0 = completely random, 1.0 = perfectly regular."""
    cv = compute_jitter_pct(intervals)
    return max(0.0, 1.0 - cv)


def closest_beacon_interval(mean_interval: float, candidate_intervals: list) -> tuple:
    """Find which configured interval is closest to observed mean."""
    if not candidate_intervals:
        return None, float("inf")
    diffs = [(abs(mean_interval - c), c) for c in candidate_intervals]
    diffs.sort()
    return diffs[0][1], diffs[0][0]


# ── Framework Scorer ──────────────────────────────────────────────────────────
def score_against_framework(beacon_data: dict, framework: str, sig: dict) -> int:
    """Score a beacon session against a specific C2 framework signature."""
    score = 0
    intervals = beacon_data.get("intervals", [])

    if not intervals:
        return 0

    mean_interval = statistics.mean(intervals) if intervals else 0
    jitter = compute_jitter_pct(intervals)

    # 1. Interval match (core signal)
    closest, diff = closest_beacon_interval(mean_interval, sig["beacon_intervals_sec"])
    if closest and diff / max(closest, 1) < 0.25:  # within 25% of known interval
        score += 30

    # 2. Jitter range match
    jitter_min, jitter_max = sig["jitter_pct_range"]
    if jitter_min <= jitter <= jitter_max:
        score += 20

    # 3. User-Agent pattern match
    ua = beacon_data.get("user_agent", "")
    for pattern in sig["default_ua_patterns"]:
        if re.search(pattern, ua, re.IGNORECASE):
            score += sig.get("confidence_boost_ua", 15)
            break

    # 4. URI pattern match
    uris = beacon_data.get("uris", [])
    for uri in uris:
        for pattern in sig["uri_patterns"]:
            if re.search(pattern, uri, re.IGNORECASE):
                score += sig.get("confidence_boost_uri", 15)
                break

    # 5. Body size range match
    avg_body = beacon_data.get("avg_body_size", 0)
    body_min, body_max = sig["body_sizes"]
    if body_min <= avg_body <= body_max:
        score += 10

    # 6. HTTP method match
    methods = beacon_data.get("http_methods", set())
    if methods and methods.issubset(set(sig["http_methods"])):
        score += 5

    return min(score, 100)


# ── Log Parser ────────────────────────────────────────────────────────────────
def parse_http_proxy_log(log_path: str) -> dict:
    """
    Parse HTTP proxy/web gateway logs (NDJSON).
    Expected: timestamp, src_ip, dst_ip, dst_host, uri, method,
              user_agent, response_size (optional)
    """
    session_tracker = defaultdict(lambda: {
        "timestamps": [],
        "uris": [],
        "user_agents": set(),
        "methods": set(),
        "response_sizes": [],
        "dst_host": "",
    })

    with open(log_path, "r") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                event = json.loads(line)
                src = event["src_ip"]
                dst = event.get("dst_ip", "")
                host = event.get("dst_host", "")
                port = event.get("dst_port", 80)
                uri = event.get("uri", "/")
                method = event.get("method", "GET").upper()
                ua = event.get("user_agent", "")
                body_size = event.get("response_size", 0)
                ts_raw = event["timestamp"]

                ts = float(ts_raw) if isinstance(ts_raw, (int, float)) else \
                    datetime.fromisoformat(ts_raw.replace("Z", "+00:00")).timestamp()

                key = f"{src}|{dst or host}:{port}"
                d = session_tracker[key]
                d["timestamps"].append(ts)
                d["uris"].append(uri)
                d["user_agents"].add(ua)
                d["methods"].add(method)
                d["response_sizes"].append(body_size)
                d["dst_host"] = host
                d["src_ip"] = src
                d["dst_ip"] = dst

            except (json.JSONDecodeError, KeyError, ValueError) as e:
                print(f"[WARN] Line {line_num}: {e}", file=sys.stderr)

    # Compute derived fields
    processed = {}
    for key, d in session_tracker.items():
        ts = sorted(d["timestamps"])
        if len(ts) < 5:
            continue
        intervals = [ts[i + 1] - ts[i] for i in range(len(ts) - 1)]
        d["intervals"] = intervals
        d["mean_interval"] = statistics.mean(intervals) if intervals else 0
        d["user_agent"] = list(d["user_agents"])[0] if d["user_agents"] else ""
        d["avg_body_size"] = statistics.mean(d["response_sizes"]) if d["response_sizes"] else 0
        d["connection_count"] = len(ts)
        d["http_methods"] = d["methods"]
        processed[key] = d

    return processed


# ── Detection Engine ──────────────────────────────────────────────────────────
def run_detection(sessions: dict) -> list:
    alerts = []

    for session_key, data in sessions.items():
        if len(data.get("intervals", [])) < 4:
            continue

        regularity = interval_regularity(data["intervals"])
        if regularity < 0.60:
            continue  # too irregular to be C2

        # Score against each known framework
        framework_scores = {}
        for framework, sig in C2_SIGNATURES.items():
            s = score_against_framework(data, framework, sig)
            if s >= 40:
                framework_scores[framework] = s

        if not framework_scores:
            continue

        top_framework = max(framework_scores, key=framework_scores.get)
        top_score = framework_scores[top_framework]
        sig = C2_SIGNATURES[top_framework]

        severity = "CRITICAL" if top_score >= 75 else \
                   "HIGH" if top_score >= 55 else "MEDIUM"

        alerts.append({
            "alert_type": "C2_FRAMEWORK_IDENTIFIED",
            "severity": severity,
            "mitre_tactic": "Command and Control",
            "mitre_technique": "T1071.001 / T1573",
            "mitre_software": sig.get("mitre_sw", ""),
            "identified_framework": top_framework,
            "confidence": top_score,
            "all_matches": framework_scores,
            "src_ip": data.get("src_ip", ""),
            "dst_ip": data.get("dst_ip", ""),
            "dst_host": data.get("dst_host", ""),
            "mean_interval_sec": round(data["mean_interval"], 2),
            "jitter_pct": round(compute_jitter_pct(data["intervals"]) * 100, 1),
            "regularity_score": round(regularity * 100, 1),
            "connection_count": data["connection_count"],
            "user_agent": data.get("user_agent", ""),
            "sample_uris": data.get("uris", [])[:3],
            "detection_timestamp": datetime.now(timezone.utc).isoformat(),
            "recommended_action": (
                f"Confirmed {top_framework} C2 channel with {top_score}% confidence. "
                "Immediate containment required. "
                "Identify implant via EDR process tree. "
                "Block C2 server at perimeter. "
                "Memory forensics for threat actor TTPs. "
                "Threat intel pivot on dst_ip/dst_host."
            ),
        })

    alerts.sort(key=lambda x: x["confidence"], reverse=True)
    return alerts


# ── Reporting ─────────────────────────────────────────────────────────────────
def print_report(alerts: list):
    print("\n" + "═" * 70)
    print("  C2 FRAMEWORK FINGERPRINTER — THREAT INTELLIGENCE REPORT")
    print("═" * 70)
    if not alerts:
        print("  ✅ No C2 framework fingerprints identified.")
        return

    print(f"  🚨 {len(alerts)} C2 session(s) identified\n")
    for i, a in enumerate(alerts, 1):
        print(f"  [{i}] {a['severity']} — {a['identified_framework']} (confidence: {a['confidence']}%)")
        print(f"      {a['src_ip']} → {a['dst_host'] or a['dst_ip']}")
        print(f"      Interval: {a['mean_interval_sec']}s | Jitter: {a['jitter_pct']}% | Regularity: {a['regularity_score']}%")
        print(f"      Connections: {a['connection_count']} | UA: {a.get('user_agent', 'N/A')[:60]}")
        if len(a["all_matches"]) > 1:
            others = {k: v for k, v in a["all_matches"].items() if k != a["identified_framework"]}
            print(f"      Other candidates: {others}")
        print(f"      MITRE: {a['mitre_technique']}")
        print()
    print("═" * 70)


def save_report(alerts: list, output_path: str):
    with open(output_path, "w") as f:
        json.dump({"total_alerts": len(alerts), "alerts": alerts}, f, indent=2)
    print(f"  📄 Report saved → {output_path}")


def main():
    log_path = sys.argv[1] if len(sys.argv) > 1 else "sample_http_proxy.ndjson"
    output_path = sys.argv[2] if len(sys.argv) > 2 else "c2_fingerprint_report.json"
    print(f"[*] Loading HTTP proxy log: {log_path}")
    sessions = parse_http_proxy_log(log_path)
    print(f"[*] Active sessions analysed: {len(sessions)}")
    alerts = run_detection(sessions)
    print_report(alerts)
    save_report(alerts, output_path)


if __name__ == "__main__":
    main()
