"""
Action Executor — Simulates SOAR playbook action execution.
Each action represents a real integration point: SIEM, firewall, ticketing,
email gateway, endpoint agent, notification channels.
"""
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class ActionExecutor:
    def execute(self, action_name, params, incident):
        method = getattr(self, f"_action_{action_name}", None)
        if not method:
            return {"status": "SKIP", "message": f"Action '{action_name}' not implemented"}
        try:
            return method(params, incident)
        except Exception as e:
            logger.error(f"Action {action_name} failed: {e}")
            return {"status": "ERROR", "message": str(e)}

    def _action_notify_analyst(self, params, incident):
        msg = params.get("message", "Alert received")
        return {"status": "OK", "detail": f"Analyst notified: {msg}",
                "channel": "Slack #soc-alerts"}

    def _action_extract_iocs(self, params, incident):
        details = incident.get("details", {})
        iocs = []
        for field in params.get("fields", []):
            val = details.get(field)
            if val:
                if isinstance(val, list):
                    iocs.extend(val)
                else:
                    iocs.append(val)
        return {"status": "OK", "iocs_extracted": iocs, "count": len(iocs)}

    def _action_reputation_check(self, params, incident):
        details = incident.get("details", {})
        urls = details.get("urls", [])
        ip = incident.get("src_ip", "")
        checked = []
        if ip:
            checked.append({"indicator": ip, "type": "ip", "verdict": "MALICIOUS",
                            "source": "AbuseIPDB"})
        for url in urls[:3]:
            checked.append({"indicator": url[:60], "type": "url", "verdict": "MALICIOUS",
                            "source": "VirusTotal"})
        return {"status": "OK", "checked": checked, "malicious_count": len(checked)}

    def _action_quarantine_email(self, params, incident):
        return {"status": "OK",
                "detail": f"Email quarantined. User notified: {params.get('notify_user')}",
                "quarantine_id": f"QID-{incident['id']}-{datetime.utcnow().strftime('%H%M%S')}"}

    def _action_block_sender_domain(self, params, incident):
        sender = incident.get("details", {}).get("sender", "unknown")
        domain = sender.split("@")[-1] if "@" in sender else sender
        return {"status": "OK", "blocked_domain": domain,
                "duration_hours": params.get("duration_hours", 72),
                "applied_to": "Email Gateway (Proofpoint)"}

    def _action_block_ip(self, params, incident):
        ip = incident.get("src_ip", "unknown")
        return {"status": "OK", "blocked_ip": ip,
                "duration_hours": params.get("duration_hours", 24),
                "applied_to": params.get("scope", "perimeter_firewall")}

    def _action_check_account_status(self, params, incident):
        user = incident.get("user", "unknown")
        return {"status": "OK", "account": user,
                "active": True, "last_successful_login": "2026-05-06T08:55:00",
                "mfa_enabled": False, "compromise_indicators": ["no_mfa", "failed_logins_spike"]}

    def _action_lock_account(self, params, incident):
        user = incident.get("user", "unknown")
        return {"status": "OK", "account_locked": user,
                "notify_user": params.get("notify_user", True),
                "password_reset_required": params.get("reset_required", True),
                "applied_via": "Active Directory"}

    def _action_geoip_lookup(self, params, incident):
        ip = incident.get("src_ip", "")
        geo_mock = {"185.220.101.47": {"country": "Russia", "city": "Moscow", "asn": "AS60068 Tor Exit"},
                    "45.142.212.100": {"country": "China", "city": "Shanghai", "asn": "AS4134 ChinaNet"},
                    "10.0.0.55": {"country": "Internal", "city": "N/A", "asn": "Internal"}}
        result = geo_mock.get(ip, {"country": "Unknown", "city": "Unknown", "asn": "Unknown"})
        return {"status": "OK", "ip": ip, "geo": result}

    def _action_isolate_host(self, params, incident):
        host = incident.get("host", "unknown")
        return {"status": "OK", "host_isolated": host,
                "method": params.get("method", "network_isolation"),
                "memory_preserved": params.get("preserve_memory", False),
                "isolation_time": datetime.utcnow().isoformat()}

    def _action_snapshot_host(self, params, incident):
        host = incident.get("host", "unknown")
        return {"status": "OK", "snapshot_created": True, "host": host,
                "includes_memory": params.get("include_memory", False),
                "includes_disk": params.get("include_disk", False),
                "snapshot_id": f"SNAP-{host}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"}

    def _action_collect_forensic_artifacts(self, params, incident):
        artifacts = params.get("artifacts", [])
        return {"status": "OK", "artifacts_collected": artifacts,
                "storage": "forensics-nas://evidence/",
                "chain_of_custody": "established"}

    def _action_block_c2_iocs(self, params, incident):
        c2_ip = incident.get("details", {}).get("c2_ip", "")
        return {"status": "OK", "blocked": [c2_ip] if c2_ip else [],
                "applied_to": "Perimeter Firewall + DNS Sinkhole"}

    def _action_notify_management(self, params, incident):
        channels = params.get("channels", [])
        return {"status": "OK", "severity": params.get("severity", "critical"),
                "notified_via": channels,
                "message": f"Critical incident {incident['id']} on {incident.get('host')}"}

    def _action_create_ticket(self, params, incident):
        return {"status": "OK",
                "ticket_id": f"TKT-{incident['id']}-{datetime.utcnow().strftime('%H%M%S')}",
                "priority": params.get("priority", "medium"),
                "queue": params.get("queue", "soc_tier1"),
                "auto_assigned": params.get("auto_assign", False),
                "platform": "ServiceNow"}

    def _action_generate_report(self, params, incident):
        return {"status": "OK", "report_format": params.get("format", "json"),
                "includes_iocs": params.get("include_iocs", False),
                "includes_timeline": params.get("include_timeline", False),
                "report_path": f"reports/{incident['id']}_report.{params.get('format','json')}"}
