"""
Supply Chain Anomaly Detector — Malicious Package & Dependency Attack Analyzer
==============================================================================
Detects software supply chain attacks: typosquatting, dependency confusion,
malicious package installs, and compromised build tools. Monitors package
manager activity (pip, npm, apt, yum) for suspicious patterns.

Real-world coverage: SolarWinds-style build injection, Log4Shell supply
chain exploitation, npm/PyPI typosquatting (event-stream, ua-parser-js).

MITRE ATT&CK:
  T1195.001 - Supply Chain Compromise: Compromise Software Dependencies
  T1195.002 - Compromise Software Supply Chain
  T1072     - Software Deployment Tools
  T1059     - Command and Scripting Interpreter (post-install hooks)

Author: Oladapo Damilola (Wizardskull)
"""

import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone


# ── Typosquatting Patterns ────────────────────────────────────────────────────
# Common legitimate packages and their known typosquats
LEGITIMATE_PACKAGES = {
    # PyPI
    "requests", "numpy", "pandas", "flask", "django", "sqlalchemy",
    "boto3", "cryptography", "paramiko", "pyyaml", "pillow", "scipy",
    "tensorflow", "torch", "fastapi", "celery", "redis", "psycopg2",
    # npm
    "express", "lodash", "axios", "react", "moment", "chalk",
    "commander", "webpack", "babel", "typescript", "eslint",
    # System
    "openssl", "libssl", "curl", "wget", "python3", "nodejs",
}

KNOWN_TYPOSQUATS = {
    # PyPI confirmed malicious (historical)
    "reqeusts", "requets", "request", "requersts",
    "nump", "numpa", "numpay",
    "flasks", "dajngo", "djnago",
    "boto", "boto33", "botto3",
    "crytography", "cryptograhy",
    "pilows", "pilliow",
    # npm confirmed malicious
    "crossenv", "cross-env.js", "event-stream",
    "flatmap-stream", "eslint-scope",
    "getcookies", "grpc-node",
    # Dependency confusion targets
    "internal-package", "company-utils", "private-lib",
}

SUSPICIOUS_PACKAGE_PATTERNS = [
    r"^[a-z]{1,3}-[a-z]{1,3}$",           # very short names
    r"\d{4,}",                              # many digits in name
    r"--",                                  # double dash
    r"^(test|temp|tmp|demo|example)\b",    # placeholder-style names
    r"_[a-f0-9]{6,}$",                     # hash suffix
]

MALICIOUS_INSTALL_SIGNALS = [
    # Post-install hooks executing network calls
    r"postinstall.*curl", r"postinstall.*wget", r"postinstall.*http",
    r"setup\.py.*urllib", r"setup\.py.*socket",
    # Encoded payloads in install scripts
    r"base64\.b64decode", r"eval\(.*base64",
    r"exec\(.*decode",
    # Suspicious install targets
    r"pip.*--index-url.*(?!pypi\.org)",    # non-PyPI index
    r"npm.*--registry.*(?!npmjs\.com)",    # non-npmjs registry
    r"pip.*--trusted-host",               # bypass SSL verification
    r"npm.*--ignore-scripts\s*=\s*false",
    # Crypto mining indicators
    r"xmrig", r"minerd", r"cryptonight",
    # Reverse shell in package
    r"subprocess.*shell.*True.*curl",
    r"os\.system.*wget",
]

VERSION_CONFUSION_PATTERNS = [
    r"999\.", r"9999\.",   # version confusion attacks use very high versions
    r"0\.0\.0",            # internal placeholder version leaked
]


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if not s2:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1,
                           prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]


def is_typosquat(package_name: str) -> dict:
    """Check if package name is a typosquat of a known legitimate package."""
    name = package_name.lower().replace("-", "").replace("_", "")

    # Direct known typosquat
    if package_name.lower() in KNOWN_TYPOSQUATS:
        return {"typosquat": True, "type": "known_malicious", "target": package_name}

    # Edit distance check against legit packages
    for legit in LEGITIMATE_PACKAGES:
        legit_norm = legit.lower().replace("-", "").replace("_", "")
        dist = levenshtein_distance(name, legit_norm)
        similarity = 1 - (dist / max(len(name), len(legit_norm)))
        if 0 < dist <= 2 and similarity >= 0.75 and name != legit_norm:
            return {
                "typosquat": True,
                "type": "edit_distance",
                "target": legit,
                "distance": dist,
                "similarity": round(similarity, 3),
            }

    return {"typosquat": False}


def check_suspicious_name(package_name: str) -> list:
    """Flag packages with suspicious naming patterns."""
    flags = []
    for pattern in SUSPICIOUS_PACKAGE_PATTERNS:
        if re.search(pattern, package_name, re.IGNORECASE):
            flags.append(f"suspicious_pattern: {pattern}")
    return flags


def check_install_command(cmdline: str) -> list:
    """Detect malicious install command patterns."""
    matches = []
    for pattern in MALICIOUS_INSTALL_SIGNALS:
        if re.search(pattern, cmdline, re.IGNORECASE):
            matches.append(pattern[:50])
    return matches


def check_version_confusion(version: str) -> bool:
    """Detect dependency confusion version attacks."""
    return any(re.search(p, version or "") for p in VERSION_CONFUSION_PATTERNS)


def parse_package_log(log_path: str) -> list:
    """
    Parse package manager activity logs (NDJSON).
    Expected: timestamp, host, user, package_manager, package_name,
              version, command_line, action (install/upgrade/download)
    """
    events = []
    with open(log_path) as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                ev = json.loads(line)
                ts_raw = ev["timestamp"]
                ts = float(ts_raw) if isinstance(ts_raw, (int, float)) else \
                    datetime.fromisoformat(ts_raw.replace("Z", "+00:00")).timestamp()
                ev["ts"] = ts
                events.append(ev)
            except (json.JSONDecodeError, KeyError, ValueError) as e:
                print(f"[WARN] Line {line_num}: {e}", file=sys.stderr)
    return events


def run_detection(events: list) -> list:
    alerts = []

    # Track install velocity per host
    host_installs = defaultdict(list)

    for ev in events:
        package = ev.get("package_name", "")
        version = ev.get("version", "")
        cmdline = ev.get("command_line", "")
        host = ev.get("host", "unknown")
        user = ev.get("user", "unknown")
        pm = ev.get("package_manager", "unknown")
        ts = ev.get("ts", 0)
        ts_str = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
        host_installs[host].append(ev)

        indicators = []
        severity = "LOW"

        # 1. Known typosquat
        typo = is_typosquat(package)
        if typo["typosquat"]:
            indicators.append(f"typosquat of '{typo.get('target', '?')}' (type: {typo['type']})")
            severity = "CRITICAL"

        # 2. Suspicious name patterns
        name_flags = check_suspicious_name(package)
        if name_flags:
            indicators.extend(name_flags)
            if severity not in ("CRITICAL",):
                severity = "MEDIUM"

        # 3. Malicious install command
        cmd_flags = check_install_command(cmdline)
        if cmd_flags:
            indicators.append(f"malicious_install_pattern: {cmd_flags[0]}")
            severity = "HIGH" if severity != "CRITICAL" else "CRITICAL"

        # 4. Version confusion
        if check_version_confusion(version):
            indicators.append(f"version_confusion_attack: {version}")
            severity = "HIGH" if severity != "CRITICAL" else "CRITICAL"

        # 5. Non-standard registry
        if "index-url" in cmdline.lower() and "pypi.org" not in cmdline:
            indicators.append("non-standard package registry")
            if severity == "LOW":
                severity = "MEDIUM"

        if indicators:
            alerts.append({
                "alert_type": "SUPPLY_CHAIN_ANOMALY",
                "severity": severity,
                "mitre_technique": "T1195.001",
                "mitre_tactic": "Initial Access",
                "host": host,
                "user": user,
                "package_manager": pm,
                "package_name": package,
                "version": version,
                "indicators": indicators,
                "command_line": cmdline[:300],
                "event_time": ts_str,
                "detection_timestamp": datetime.now(timezone.utc).isoformat(),
                "recommended_action": (
                    f"Block installation of '{package}' immediately. "
                    "Check if package was successfully installed and remove it. "
                    "Scan host for post-install payload execution. "
                    "Review package in upstream registry for malicious code. "
                    "Alert dev team — check all requirements.txt / package.json for compromise."
                ),
            })

    # Velocity alert: rapid mass installs (build system compromise)
    for host, evts in host_installs.items():
        if len(evts) >= 20:
            window = max(e["ts"] for e in evts) - min(e["ts"] for e in evts)
            if window < 120:  # 20+ installs in 2 minutes
                alerts.append({
                    "alert_type": "MASS_PACKAGE_INSTALL",
                    "severity": "HIGH",
                    "mitre_technique": "T1072",
                    "mitre_tactic": "Execution",
                    "host": host,
                    "install_count": len(evts),
                    "window_seconds": round(window, 1),
                    "description": f"Mass package install on {host}: {len(evts)} packages in {window:.0f}s — possible build system compromise or dependency confusion attack",
                    "detection_timestamp": datetime.now(timezone.utc).isoformat(),
                    "recommended_action": "Investigate CI/CD pipeline. Review build logs for injected steps.",
                })

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    alerts.sort(key=lambda x: sev_order.get(x.get("severity", "LOW"), 9))
    return alerts


def print_report(alerts: list):
    print("\n" + "═" * 70)
    print("  SUPPLY CHAIN ANOMALY DETECTOR — THREAT REPORT")
    print("═" * 70)
    if not alerts:
        print("  ✅ No supply chain anomalies detected.")
        return
    critical = sum(1 for a in alerts if a.get("severity") == "CRITICAL")
    print(f"  🚨 {len(alerts)} alert(s): {critical} CRITICAL\n")
    for i, a in enumerate(alerts, 1):
        print(f"  [{i}] {a['severity']} — {a['alert_type']}")
        print(f"      Host: {a.get('host')} | Package: {a.get('package_name', 'N/A')} v{a.get('version', '?')}")
        print(f"      Indicators: {' | '.join(a.get('indicators', [a.get('description','')]))}")
        print(f"      MITRE: {a['mitre_technique']}")
        print()
    print("═" * 70)


def save_report(alerts, path):
    with open(path, "w") as f:
        json.dump({"total_alerts": len(alerts), "alerts": alerts}, f, indent=2)
    print(f"  📄 Report saved → {path}")


def main():
    log_path = sys.argv[1] if len(sys.argv) > 1 else "sample_packages.ndjson"
    out_path = sys.argv[2] if len(sys.argv) > 2 else "supply_chain_report.json"
    print(f"[*] Loading package manager log: {log_path}")
    events = parse_package_log(log_path)
    print(f"[*] Package events: {len(events)}")
    alerts = run_detection(events)
    print_report(alerts)
    save_report(alerts, out_path)


if __name__ == "__main__":
    main()
