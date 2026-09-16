"""Incident Timeline Report Generator — produces forensic-style IR report."""
from datetime import datetime

class ReportGenerator:
    def generate(self, recon):
        r = []
        r.append("="*68)
        r.append("  INCIDENT TIMELINE RECONSTRUCTION REPORT")
        r.append(f"  Generated       : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        r.append(f"  Attack Start    : {recon['attack_start']}")
        r.append(f"  Attack End      : {recon['attack_end']}")
        r.append(f"  Total Dwell Time: {recon['dwell_time_minutes']} minutes")
        r.append(f"  Patient Zero    : {recon['patient_zero']}")
        r.append(f"  Events Analysed : {recon['total_events']}")
        r.append(f"  Phases Detected : {len(recon['phases_detected'])}")
        r.append("="*68)

        r.append("\n  MITRE ATT&CK KILL CHAIN PROGRESSION\n")
        for pt in recon["phase_timing"]:
            gap = f"  (+{pt.get('minutes_after_previous','')}min)" if pt.get("minutes_after_previous") is not None else ""
            r.append(f"  [{pt['phase']:<25}] {pt['first_seen'][:19]}  {pt['event_count']} event(s){gap}")

        r.append("\n\n  CHRONOLOGICAL EVENT TIMELINE\n")
        for ev in recon["timeline"]:
            r.append(f"  {ev.get('timestamp','')[:19]}  [{ev.get('source','?'):<18}] [{ev.get('phase','?'):<22}]")
            r.append(f"    {ev.get('mitre','')}  —  {ev.get('detail','')}")
            r.append("")

        r.append("  INDICATORS OF COMPROMISE\n")
        iocs = recon["iocs"]
        r.append(f"  Attacker IPs       : {', '.join(iocs['attacker_ips'])}")
        r.append(f"  Hosts Compromised  : {', '.join(iocs['hosts_compromised'])}")
        r.append(f"  MITRE Techniques   : {len(iocs['mitre_techniques'])} unique technique(s)")
        for t in sorted(iocs["mitre_techniques"]):
            r.append(f"    {t}")
        r.append("\n" + "="*68)
        return "\n".join(r)
