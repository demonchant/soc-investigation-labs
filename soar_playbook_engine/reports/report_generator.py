"""SOAR Playbook Execution Report Generator."""
from datetime import datetime

STATUS_LABEL = {"OK":"[OK]","FAIL":"[FAIL]","SKIP":"[SKIP]","UNKNOWN":"[?]"}

class ReportGenerator:
    def generate(self, executions):
        r = []
        completed = sum(1 for e in executions if e["final_status"]=="COMPLETED")
        r.append("="*65)
        r.append("  SOAR PLAYBOOK EXECUTION REPORT")
        r.append(f"  Generated  : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        r.append(f"  Playbooks  : {len(executions)} executed  |  {completed} completed")
        r.append("="*65)
        for ex in executions:
            r.append(f"\n  Playbook : {ex['playbook_name']} [{ex['playbook_id']}]")
            r.append(f"  Incident : {ex['incident_id']}  |  Status: {ex['final_status']}")
            r.append(f"  MITRE    : {ex['mitre']}")
            r.append(f"  Steps    : {ex['steps_passed']}/{ex['steps_total']} passed"
                     + (f"  | ESCALATED" if ex["escalated"] else ""))
            r.append(f"  Started  : {ex['started_at']}  Completed: {ex.get('completed_at','')}")
            r.append("\n  Step Audit Trail:")
            for s in ex["steps_executed"]:
                lbl = STATUS_LABEL.get(s["status"],"[?]")
                r.append(f"    {lbl} Step {s['step']:02d}: {s['action']}")
                res = s.get("result",{})
                for k,v in res.items():
                    if k not in ("action","status") and v not in (None,"","[]",{},[]):
                        r.append(f"           {str(k):<24}: {str(v)[:60]}")
            r.append("")
        r.append("="*65)
        return "\n".join(r)
