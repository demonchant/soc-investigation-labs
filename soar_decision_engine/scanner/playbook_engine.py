"""
SOAR Playbook Engine — Automated Incident Response Orchestrator
Executes structured IR playbooks with decision trees, approval gates,
SLA tracking, and rollback logging.
"""
import logging
from collections import defaultdict
logger = logging.getLogger(__name__)

MITRE = {
    "contain":   "RS0001 - Containment (NIST IR Phase)",
    "eradicate": "RS0002 - Eradication (NIST IR Phase)",
    "recover":   "RS0003 - Recovery (NIST IR Phase)",
    "notify":    "RS0004 - Communication (NIST IR Phase)",
    "escalate":  "RS0005 - Escalation (NIST IR Phase)",
}

PLAYBOOKS = {
    "credential_compromise": {
        "name": "Credential Compromise Response",
        "sla_minutes": 30,
        "steps": [
            {"id":"CC-01","action":"lookup_user_context","description":"Pull user role, dept, recent auth history","automated":True,"approval_required":False,"phase":"contain","rollback":None,"expected_duration_min":1},
            {"id":"CC-02","action":"disable_user_account","description":"Disable compromised account in IdP/AD","automated":True,"approval_required":False,"phase":"contain","rollback":"re_enable_user_account","expected_duration_min":2},
            {"id":"CC-03","action":"revoke_active_sessions","description":"Terminate all active SSO/OAuth sessions","automated":True,"approval_required":False,"phase":"contain","rollback":None,"expected_duration_min":1},
            {"id":"CC-04","action":"notify_user_manager","description":"Email manager: account disabled pending investigation","automated":True,"approval_required":False,"phase":"notify","rollback":None,"expected_duration_min":1},
            {"id":"CC-05","action":"collect_auth_logs_30d","description":"Pull 30 days auth logs for forensic timeline","automated":True,"approval_required":False,"phase":"eradicate","rollback":None,"expected_duration_min":5},
            {"id":"CC-06","action":"check_lateral_movement","description":"Query SIEM: did account authenticate to other hosts?","automated":True,"approval_required":False,"phase":"eradicate","rollback":None,"expected_duration_min":3},
            {"id":"CC-07","action":"analyst_verdict","description":"Analyst reviews evidence, confirms compromise or FP","automated":False,"approval_required":True,"phase":"eradicate","rollback":None,"expected_duration_min":15},
            {"id":"CC-08","action":"force_password_reset","description":"Trigger forced reset + MFA re-enroll on next login","automated":True,"approval_required":False,"phase":"recover","rollback":None,"expected_duration_min":2},
        ]
    },
    "malware_on_endpoint": {
        "name": "Malware Endpoint Response",
        "sla_minutes": 15,
        "steps": [
            {"id":"ME-01","action":"isolate_host","description":"Quarantine endpoint via EDR network isolation","automated":True,"approval_required":False,"phase":"contain","rollback":"restore_host_network","expected_duration_min":1},
            {"id":"ME-02","action":"collect_memory_snapshot","description":"Trigger live memory acquisition before reboot","automated":True,"approval_required":False,"phase":"contain","rollback":None,"expected_duration_min":5},
            {"id":"ME-03","action":"block_hash_fleet","description":"Push hash block rule to entire EDR fleet","automated":True,"approval_required":False,"phase":"contain","rollback":"remove_hash_block","expected_duration_min":2},
            {"id":"ME-04","action":"fleet_hunt_hash","description":"Fleet-wide hunt: any other host with same hash?","automated":True,"approval_required":False,"phase":"eradicate","rollback":None,"expected_duration_min":8},
            {"id":"ME-05","action":"check_c2_outbound","description":"Query firewall: did host make outbound C2 connections?","automated":True,"approval_required":False,"phase":"eradicate","rollback":None,"expected_duration_min":3},
            {"id":"ME-06","action":"senior_analyst_escalation","description":"Escalate to senior analyst if C2 detected","automated":False,"approval_required":True,"phase":"escalate","rollback":None,"expected_duration_min":20},
            {"id":"ME-07","action":"reimage_host","description":"Schedule host reimaging via SCCM/MDM","automated":True,"approval_required":True,"phase":"recover","rollback":None,"expected_duration_min":60},
        ]
    },
    "phishing_email": {
        "name": "Phishing Email Response",
        "sla_minutes": 60,
        "steps": [
            {"id":"PE-01","action":"extract_artifacts","description":"Extract sender, URLs, attachments, headers","automated":True,"approval_required":False,"phase":"contain","rollback":None,"expected_duration_min":2},
            {"id":"PE-02","action":"check_urls_ti","description":"Submit URLs to threat intel reputation check","automated":True,"approval_required":False,"phase":"contain","rollback":None,"expected_duration_min":2},
            {"id":"PE-03","action":"search_similar_emails","description":"Did other users receive the same email?","automated":True,"approval_required":False,"phase":"contain","rollback":None,"expected_duration_min":5},
            {"id":"PE-04","action":"bulk_delete_emails","description":"Remove matching emails from all mailboxes org-wide","automated":True,"approval_required":True,"phase":"eradicate","rollback":"restore_bulk_deleted","expected_duration_min":10},
            {"id":"PE-05","action":"block_sender_domain","description":"Add sender domain to email gateway blocklist","automated":True,"approval_required":False,"phase":"eradicate","rollback":"remove_sender_block","expected_duration_min":1},
            {"id":"PE-06","action":"check_users_clicked","description":"Query proxy: did any user click the phishing URL?","automated":True,"approval_required":False,"phase":"eradicate","rollback":None,"expected_duration_min":5},
            {"id":"PE-07","action":"notify_clicked_users","description":"Alert users who clicked; trigger credential reset","automated":True,"approval_required":False,"phase":"notify","rollback":None,"expected_duration_min":5},
        ]
    }
}

class PlaybookEngine:
    def __init__(self): self.findings = []

    def run_all(self, data):
        for inc in data.get("incidents", []):
            self._execute(inc)
        return self.findings

    def _f(self, inc_id, pb_name, title, sev, detail, mitre, rec):
        self.findings.append({"incident_id": inc_id, "playbook": pb_name,
            "title": title, "severity": sev, "detail": detail,
            "mitre_technique": mitre, "recommendation": rec})

    def _execute(self, inc):
        inc_id  = inc.get("incident_id", "?")
        pb_key  = inc.get("playbook_type", "")
        pb      = PLAYBOOKS.get(pb_key)

        if not pb:
            self._f(inc_id, "UNKNOWN", "No Playbook Matched: {}".format(pb_key), "high",
                "Incident type '{}' has no defined playbook — fully manual response.".format(pb_key),
                MITRE["escalate"],
                "Create a playbook for this incident type. Document all response steps.")
            return

        sla_min  = pb["sla_minutes"]
        start_ts = inc.get("detected_epoch", 0)
        now_ts   = inc.get("current_epoch",  start_ts + 900)
        elapsed  = (now_ts - start_ts) / 60
        completed = set(inc.get("completed_steps", []))
        total     = len(pb["steps"])
        auto_steps= sum(1 for s in pb["steps"] if s["automated"] and not s["approval_required"])

        # SLA tracking
        if elapsed > sla_min:
            self._f(inc_id, pb["name"],
                "SLA BREACH: {:.0f}/{} min elapsed".format(elapsed, sla_min), "critical",
                "Incident exceeded the {}-minute SLA by {:.0f} minutes.".format(
                    sla_min, elapsed - sla_min),
                MITRE["escalate"],
                "Escalate immediately. Log breach for post-incident review.")

        # Pending approvals
        for step in pb["steps"]:
            if step["id"] in completed: continue
            if step["approval_required"]:
                self._f(inc_id, pb["name"],
                    "Approval Required: [{}] {}".format(step["id"], step["action"]), "medium",
                    "Step '{}' awaiting analyst approval. Est. duration: {} min. Phase: {}.".format(
                        step["description"], step["expected_duration_min"], step["phase"]),
                    MITRE.get(step["phase"], MITRE["contain"]),
                    "Review prerequisites and approve or reject in ticketing system.")

        # Rollback tracking
        rollbacks = [s for s in pb["steps"] if s["id"] in completed and s.get("rollback")]
        if rollbacks:
            self._f(inc_id, pb["name"],
                "Rollback Available: {} reversible step(s)".format(len(rollbacks)), "low",
                "Steps with rollback capability: {}.".format(
                    ", ".join(r["id"] for r in rollbacks)),
                MITRE["recover"],
                "If confirmed false positive, rollback actions are available — approve and log.")

        # Progress
        pct = len(completed) / total * 100 if total else 0
        sev = "low" if pct >= 80 else "medium" if pct >= 40 else "high"
        next_step = next((s["description"] for s in pb["steps"]
                          if s["id"] not in completed), "All steps complete.")
        self._f(inc_id, pb["name"],
            "Playbook Progress: {:.0f}% ({}/{} steps)".format(pct, len(completed), total), sev,
            "SLA: {} min | Elapsed: {:.0f} min | Auto-executable: {}/{}.".format(
                sla_min, elapsed, auto_steps, total),
            MITRE["contain"],
            "Next action: {}.".format(next_step))
