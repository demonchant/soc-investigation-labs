"""
Playbook Runner — Matches incidents to playbooks by trigger field,
executes steps sequentially, handles on_fail branching, produces audit trail.
"""
import time, logging
from actions.action_library import ActionLibrary
logger = logging.getLogger(__name__)

class PlaybookRunner:
    def __init__(self):
        self.lib = ActionLibrary()

    def find_playbook(self, playbooks, trigger):
        """Find playbook whose 'trigger' field matches the incident type."""
        for pb in playbooks.values():
            if pb.get("trigger") == trigger:
                return pb
        return None

    def run(self, playbook, incident):
        execution = {
            "playbook_id": playbook["id"],
            "playbook_name": playbook["name"],
            "incident_id": incident["id"],
            "trigger": playbook["trigger"],
            "mitre": playbook.get("mitre",""),
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "steps_executed": [],
            "steps_total": len(playbook["steps"]),
            "steps_passed": 0, "steps_failed": 0,
            "escalated": False, "final_status": "RUNNING"
        }
        for step_def in playbook["steps"]:
            action = step_def["action"]
            params = step_def.get("params", {})
            on_fail = step_def.get("on_fail", "continue")
            result = self.lib.execute(action, params, incident)
            step_record = {"step": step_def["step"], "action": action,
                           "status": result.get("status","UNKNOWN"), "result": result}
            execution["steps_executed"].append(step_record)
            if result.get("status") in ("OK","SKIP"):
                execution["steps_passed"] += 1
            else:
                execution["steps_failed"] += 1
                if on_fail == "stop":
                    execution["final_status"] = "STOPPED"; break
                elif on_fail == "escalate":
                    execution["escalated"] = True
                    execution["final_status"] = "ESCALATED"; break
        if execution["final_status"] == "RUNNING":
            execution["final_status"] = "COMPLETED"
        execution["completed_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        return execution
