"""
Alert Manager — Stores and retrieves security alerts.
"""
from datetime import datetime

alerts_store = []

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def create_alert(title, severity, mitre, description, log):
    alert = {
        "title": title,
        "severity": severity,
        "mitre_technique": mitre,
        "description": description,
        "user": log.get("user", "unknown"),
        "event": log.get("event_name"),
        "source_ip": log.get("source_ip"),
        "region": log.get("region"),
        "mfa_used": log.get("mfa_used"),
        "time": datetime.utcnow().isoformat()
    }
    alerts_store.append(alert)


def get_alerts(severity_filter=None):
    if severity_filter:
        return [a for a in alerts_store if a["severity"] == severity_filter]
    return sorted(alerts_store, key=lambda a: SEVERITY_ORDER.get(a["severity"], 99))


def clear_alerts():
    alerts_store.clear()
