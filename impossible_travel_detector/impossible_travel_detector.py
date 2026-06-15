"""
Impossible Travel Detector — Geospatial Authentication Anomaly Engine
=====================================================================
Detects account compromise by identifying logins from geographically
impossible locations. If a user logs in from Lagos at 10:00 AM and
then from London at 10:30 AM — that's physically impossible and
indicates credential theft or VPN/proxy abuse.

Uses Haversine formula for great-circle distance calculation.
No external APIs required — all geo data embedded.

MITRE ATT&CK:
  T1078     - Valid Accounts
  T1078.004 - Cloud Accounts
  T1133     - External Remote Services
  T1110     - Brute Force (post-compromise indicator)

Author: Oladapo Damilola (Wizardskull)
"""

import json
import math
import sys
from collections import defaultdict
from datetime import datetime, timezone


# ── Configuration ─────────────────────────────────────────────────────────────
CONFIG = {
    "max_travel_speed_kmh": 900,     # Concorde-era max; commercial: ~900 km/h
    "min_distance_km": 100,          # below this distance, don't flag (VPN/CDN noise)
    "risk_distance_threshold_km": 5000,  # transcontinental = high risk
    "tor_exit_boost": 30,            # extra risk score for known Tor/VPN IPs
    "time_window_hours": 24,         # only compare logins within this window
}

# ── Embedded IP → Geo Mapping (sample; production uses MaxMind GeoIP2) ────────
# Format: ip_prefix → (city, country, lat, lon)
# Real deployment: replace with MaxMind GeoLite2 lookup
SAMPLE_GEO_DB = {
    "102.89": ("Lagos", "Nigeria", 6.5244, 3.3792),
    "41.58":  ("Lagos", "Nigeria", 6.5244, 3.3792),
    "62.253": ("London", "United Kingdom", 51.5074, -0.1278),
    "88.98":  ("London", "United Kingdom", 51.5074, -0.1278),
    "8.8":    ("Mountain View", "United States", 37.4056, -122.0775),
    "104.16": ("San Francisco", "United States", 37.7749, -122.4194),
    "45.33":  ("Dallas", "United States", 32.7767, -96.7970),
    "185.220": ("Amsterdam", "Netherlands", 52.3676, 4.9041),  # common Tor exit
    "198.98":  ("Unknown", "TOR", 0.0, 0.0),  # Tor exit node
    "91.108":  ("Moscow", "Russia", 55.7558, 37.6173),
    "95.216":  ("Helsinki", "Finland", 60.1699, 24.9384),
    "52.168":  ("Dublin", "Ireland", 53.3331, -6.2489),  # Azure IE
    "13.107":  ("Seattle", "United States", 47.6062, -122.3321),  # Microsoft
    "17.253":  ("Cupertino", "United States", 37.3229, -122.0322),  # Apple
    "203.0":   ("Sydney", "Australia", -33.8688, 151.2093),
    "1.1":     ("Brisbane", "Australia", -27.4698, 153.0251),  # Cloudflare
    "54.239":  ("Ashburn", "United States", 39.0438, -77.4874),  # AWS
}

KNOWN_VPN_TOR_RANGES = {"185.220.", "198.98.", "104.244.", "162.247.", "23.129."}


# ── Haversine Formula ─────────────────────────────────────────────────────────
def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate great-circle distance between two coordinates in km."""
    R = 6371  # Earth radius in km
    d_lat = math.radians(lat2 - lat1)
    d_lon = math.radians(lon2 - lon1)
    a = (math.sin(d_lat / 2) ** 2 +
         math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *
         math.sin(d_lon / 2) ** 2)
    return R * 2 * math.asin(math.sqrt(a))


def required_speed_kmh(distance_km: float, time_seconds: float) -> float:
    """Speed required to travel distance in given time."""
    if time_seconds <= 0:
        return float("inf")
    return distance_km / (time_seconds / 3600)


# ── Geo Lookup ────────────────────────────────────────────────────────────────
def geo_lookup(ip: str) -> dict:
    """Look up approximate geo data for an IP address."""
    # Check full prefix first, then shorter
    for prefix_len in [7, 6, 5, 4, 3]:
        prefix = ".".join(ip.split(".")[:2])[:prefix_len]
        for db_prefix, geo_data in SAMPLE_GEO_DB.items():
            if db_prefix.startswith(prefix) or prefix.startswith(db_prefix[:prefix_len]):
                city, country, lat, lon = geo_data
                is_vpn_tor = any(ip.startswith(r) for r in KNOWN_VPN_TOR_RANGES)
                return {
                    "city": city,
                    "country": country,
                    "lat": lat,
                    "lon": lon,
                    "is_vpn_tor": is_vpn_tor or country == "TOR",
                }

    # Fallback: unknown location
    return {"city": "Unknown", "country": "Unknown", "lat": 0.0, "lon": 0.0, "is_vpn_tor": False}


# ── Log Parser ────────────────────────────────────────────────────────────────
def parse_auth_log(log_path: str) -> dict:
    """
    Parse authentication logs. Groups events by username.
    Expected: timestamp, username, ip, status, service (optional)
    """
    user_logins = defaultdict(list)

    with open(log_path, "r") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                event = json.loads(line)
                if event.get("status", "").lower() != "success":
                    continue  # only successful logins matter for travel

                ts_raw = event["timestamp"]
                ts = float(ts_raw) if isinstance(ts_raw, (int, float)) else \
                    datetime.fromisoformat(ts_raw.replace("Z", "+00:00")).timestamp()

                username = event["username"].lower()
                ip = event["ip"]
                geo = geo_lookup(ip)

                user_logins[username].append({
                    "ts": ts,
                    "ip": ip,
                    "service": event.get("service", "unknown"),
                    "geo": geo,
                    "ts_human": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
                })

            except (json.JSONDecodeError, KeyError, ValueError) as e:
                print(f"[WARN] Line {line_num}: {e}", file=sys.stderr)

    return dict(user_logins)


# ── Detection Engine ──────────────────────────────────────────────────────────
def check_impossible_travel(username: str, logins: list) -> list:
    """Compare consecutive logins for impossible travel patterns."""
    alerts = []
    sorted_logins = sorted(logins, key=lambda x: x["ts"])
    window_secs = CONFIG["time_window_hours"] * 3600

    for i in range(len(sorted_logins) - 1):
        login_a = sorted_logins[i]
        login_b = sorted_logins[i + 1]

        time_diff_secs = login_b["ts"] - login_a["ts"]
        if time_diff_secs > window_secs:
            continue  # too far apart to be relevant

        geo_a = login_a["geo"]
        geo_b = login_b["geo"]

        # Skip if geo is unknown for both
        if geo_a["lat"] == 0 and geo_b["lat"] == 0:
            continue

        distance_km = haversine_km(geo_a["lat"], geo_a["lon"],
                                    geo_b["lat"], geo_b["lon"])

        if distance_km < CONFIG["min_distance_km"]:
            continue  # same city / same CDN

        speed_kmh = required_speed_kmh(distance_km, time_diff_secs)

        # Risk scoring
        risk_score = 0
        indicators = []

        if speed_kmh > CONFIG["max_travel_speed_kmh"]:
            risk_score += 60
            indicators.append(f"physically impossible: {speed_kmh:.0f} km/h required")

        if distance_km >= CONFIG["risk_distance_threshold_km"]:
            risk_score += 20
            indicators.append(f"intercontinental jump: {distance_km:.0f} km")

        if geo_a["is_vpn_tor"] or geo_b["is_vpn_tor"]:
            risk_score += CONFIG["tor_exit_boost"]
            indicators.append("VPN/Tor exit node detected")

        if time_diff_secs < 300:  # < 5 minutes between distant logins
            risk_score += 20
            indicators.append(f"only {time_diff_secs:.0f}s between logins")

        if risk_score < 40:
            continue

        severity = "CRITICAL" if risk_score >= 80 else \
                   "HIGH" if risk_score >= 60 else "MEDIUM"

        alerts.append({
            "alert_type": "IMPOSSIBLE_TRAVEL",
            "severity": severity,
            "mitre_tactic": "Initial Access / Defense Evasion",
            "mitre_technique": "T1078",
            "username": username,
            "risk_score": min(risk_score, 100),
            "indicators": indicators,
            "login_a": {
                "ip": login_a["ip"],
                "location": f"{geo_a['city']}, {geo_a['country']}",
                "time": login_a["ts_human"],
                "service": login_a["service"],
            },
            "login_b": {
                "ip": login_b["ip"],
                "location": f"{geo_b['city']}, {geo_b['country']}",
                "time": login_b["ts_human"],
                "service": login_b["service"],
            },
            "distance_km": round(distance_km, 1),
            "time_between_logins_minutes": round(time_diff_secs / 60, 1),
            "required_speed_kmh": round(speed_kmh, 1),
            "detection_timestamp": datetime.now(timezone.utc).isoformat(),
            "recommended_action": (
                f"Account {username} shows impossible travel. "
                "Force MFA re-verification immediately. "
                "Review all recent account activity. "
                "Check for OAuth token theft or session hijacking. "
                "Consider account suspension pending investigation."
            ),
        })

    return alerts


def run_detection(user_logins: dict) -> list:
    all_alerts = []
    for username, logins in user_logins.items():
        if len(logins) < 2:
            continue
        alerts = check_impossible_travel(username, logins)
        all_alerts.extend(alerts)

    all_alerts.sort(key=lambda x: x["risk_score"], reverse=True)
    return all_alerts


# ── Reporting ─────────────────────────────────────────────────────────────────
def print_report(alerts: list):
    print("\n" + "═" * 70)
    print("  IMPOSSIBLE TRAVEL DETECTOR — THREAT REPORT")
    print("═" * 70)
    if not alerts:
        print("  ✅ No impossible travel detected.")
        return

    print(f"  🚨 {len(alerts)} impossible travel event(s)\n")
    for i, a in enumerate(alerts, 1):
        la, lb = a["login_a"], a["login_b"]
        print(f"  [{i}] {a['severity']} — Risk: {a['risk_score']}/100 | {a['username']}")
        print(f"      {la['location']} ({la['ip']}) at {la['time']}")
        print(f"      → {lb['location']} ({lb['ip']}) at {lb['time']}")
        print(f"      Distance: {a['distance_km']} km | Time: {a['time_between_logins_minutes']} min | Speed: {a['required_speed_kmh']} km/h")
        print(f"      Indicators: {' | '.join(a['indicators'])}")
        print(f"      MITRE: {a['mitre_technique']}")
        print()
    print("═" * 70)


def save_report(alerts: list, output_path: str):
    with open(output_path, "w") as f:
        json.dump({"total_alerts": len(alerts), "alerts": alerts}, f, indent=2)
    print(f"  📄 Report saved → {output_path}")


def main():
    log_path = sys.argv[1] if len(sys.argv) > 1 else "sample_auth_logins.ndjson"
    output_path = sys.argv[2] if len(sys.argv) > 2 else "impossible_travel_report.json"
    print(f"[*] Loading login log: {log_path}")
    user_logins = parse_auth_log(log_path)
    print(f"[*] Unique users: {len(user_logins)}")
    alerts = run_detection(user_logins)
    print_report(alerts)
    save_report(alerts, output_path)


if __name__ == "__main__":
    main()
