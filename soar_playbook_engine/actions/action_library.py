"""
Action Library — Simulates SOAR automated response actions.
Each action logs its execution, returns a result dict, and supports
success/failure states for playbook branching logic.
"""
import time, logging, random
logger = logging.getLogger(__name__)

class ActionLibrary:
    def execute(self, action_name, params, incident):
        handler = getattr(self, f"_action_{action_name}", None)
        if not handler:
            return {"status":"SKIP","action":action_name,"reason":"No handler registered"}
        try:
            result = handler(params, incident)
            result["action"] = action_name
            return result
        except Exception as e:
            logger.error(f"Action '{action_name}' failed: {e}")
            return {"status":"FAIL","action":action_name,"error":str(e)}

    def _action_notify_analyst(self, p, inc):
        return {"status":"OK","channel":"slack+email","message":p.get("message",""),
                "incident_id":inc["id"],"notified_at":time.strftime("%Y-%m-%dT%H:%M:%S")}

    def _action_extract_iocs(self, p, inc):
        d = inc.get("details",{})
        iocs = {"domains":[],"ips":[],"urls":[],"hashes":[]}
        iocs["ips"].append(inc.get("src_ip",""))
        iocs["urls"].extend(d.get("urls",[]))
        if d.get("c2_ip"): iocs["ips"].append(d["c2_ip"])
        return {"status":"OK","iocs_extracted":iocs,"count":sum(len(v) for v in iocs.values())}

    def _action_reputation_check(self, p, inc):
        # Simulated — in production would call VirusTotal/AbuseIPDB
        reps = {"185.220.101.47":"malicious","45.142.212.100":"malicious",
                "194.165.16.72":"malicious","10.0.0.55":"clean"}
        ip = inc.get("src_ip","")
        rep = reps.get(ip, "unknown")
        return {"status":"OK","ip":ip,"reputation":rep,
                "sources":["VirusTotal","AbuseIPDB"],"risk_score":90 if rep=="malicious" else 5}

    def _action_quarantine_email(self, p, inc):
        return {"status":"OK","email_quarantined":True,
                "user_notified":p.get("notify_user",False),"reason":p.get("reason","")}

    def _action_block_sender_domain(self, p, inc):
        d = inc.get("details",{})
        domain = d.get("sender","").split("@")[-1] if "@" in d.get("sender","") else "unknown"
        return {"status":"OK","domain_blocked":domain,
                "duration_hours":p.get("duration_hours",24),"scope":"email_gateway"}

    def _action_block_ip(self, p, inc):
        return {"status":"OK","ip_blocked":inc.get("src_ip",""),
                "duration_hours":p.get("duration_hours",24),
                "scope":p.get("scope","perimeter_firewall")}

    def _action_check_account_status(self, p, inc):
        return {"status":"OK","account":inc.get("user",""),"account_active":True,
                "mfa_enabled":False,"last_successful_login":"2026-05-06T08:55:00",
                "compromise_indicators":["no MFA","login from high-risk country"]}

    def _action_lock_account(self, p, inc):
        return {"status":"OK","account_locked":inc.get("user",""),
                "reset_required":p.get("reset_required",True),
                "user_notified":p.get("notify_user",True)}

    def _action_geoip_lookup(self, p, inc):
        geo = {"185.220.101.47":{"country":"Russia","city":"Moscow","isp":"Tor Exit Node"},
               "45.142.212.100":{"country":"China","city":"Shenzhen","isp":"Unknown VPS"},
               "194.165.16.72":{"country":"North Korea","city":"Pyongyang","isp":"KPTC"}}
        ip = inc.get("src_ip","")
        return {"status":"OK","ip":ip,"geo":geo.get(ip,{"country":"Unknown"})}

    def _action_isolate_host(self, p, inc):
        return {"status":"OK","host_isolated":inc.get("host",""),
                "method":p.get("method","network_isolation"),
                "memory_preserved":p.get("preserve_memory",True),
                "isolation_time":time.strftime("%Y-%m-%dT%H:%M:%S")}

    def _action_snapshot_host(self, p, inc):
        return {"status":"OK","snapshot_created":True,"host":inc.get("host",""),
                "includes_memory":p.get("include_memory",True),
                "includes_disk":p.get("include_disk",True),
                "snapshot_id":"SNAP-" + inc["id"]}

    def _action_collect_forensic_artifacts(self, p, inc):
        arts = p.get("artifacts",["processes","network_connections"])
        collected = {a: f"artifact_{a}.json" for a in arts}
        return {"status":"OK","artifacts_collected":collected,"host":inc.get("host","")}

    def _action_block_c2_iocs(self, p, inc):
        d = inc.get("details",{})
        blocked = []
        if d.get("c2_ip"): blocked.append(d["c2_ip"])
        return {"status":"OK","iocs_blocked":blocked,"scope":"perimeter_firewall+proxy"}

    def _action_notify_management(self, p, inc):
        return {"status":"OK","severity":p.get("severity","high"),
                "channels_notified":p.get("channels",["email"]),
                "escalated_to":"CISO + SOC Manager"}

    def _action_create_ticket(self, p, inc):
        ticket_id = f"TKT-{inc['id'].replace('INC-','')}-{int(time.time())%10000}"
        return {"status":"OK","ticket_id":ticket_id,"priority":p.get("priority","medium"),
                "queue":p.get("queue","soc_tier1"),"auto_assigned":p.get("auto_assign",False)}

    def _action_generate_report(self, p, inc):
        return {"status":"OK","report_generated":True,"format":p.get("format","json"),
                "includes_iocs":p.get("include_iocs",False),
                "report_path":f"reports/{inc['id']}_report.{p.get('format','json')}"}
