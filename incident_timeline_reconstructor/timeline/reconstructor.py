"""
Timeline Reconstructor — Sorts evidence chronologically, maps each event
to MITRE ATT&CK kill chain phases, calculates dwell times between phases,
and identifies the patient-zero host.
"""
from datetime import datetime
from collections import defaultdict

PHASE_ORDER = [
    "Reconnaissance","Initial Access","Execution","Command & Control",
    "Persistence","Credential Access","Lateral Movement","Discovery",
    "Privilege Escalation","Collection","Exfiltration","Impact"
]

def _ts(s):
    try: return datetime.fromisoformat(str(s))
    except: return None

class TimelineReconstructor:
    def reconstruct(self, evidence):
        sorted_ev = sorted(evidence, key=lambda e: str(e.get("timestamp","")))

        # Phase grouping
        phase_events = defaultdict(list)
        phase_first = {}
        for ev in sorted_ev:
            phase = ev.get("phase","Unknown")
            phase_events[phase].append(ev)
            t = _ts(ev.get("timestamp"))
            if t and (phase not in phase_first or t < phase_first[phase]):
                phase_first[phase] = t

        # Dwell time between first and last event
        all_times = [_ts(e.get("timestamp")) for e in sorted_ev if _ts(e.get("timestamp"))]
        dwell_minutes = round((max(all_times) - min(all_times)).total_seconds() / 60, 1) if all_times else 0

        # Attack progression
        phases_present = [p for p in PHASE_ORDER if p in phase_events]
        phase_timing = []
        for i, phase in enumerate(phases_present):
            t = phase_first.get(phase)
            entry = {"phase": phase, "first_seen": t.isoformat() if t else "", "event_count": len(phase_events[phase])}
            if i > 0:
                prev_t = phase_first.get(phases_present[i-1])
                if t and prev_t:
                    entry["minutes_after_previous"] = round((t - prev_t).total_seconds() / 60, 1)
            phase_timing.append(entry)

        # Patient zero
        hosts = [e.get("host","") for e in sorted_ev if e.get("phase") in ("Initial Access","Execution")]
        patient_zero = hosts[0] if hosts else "Unknown"

        # IOCs
        iocs = {
            "attacker_ips": list({e.get("src_ip") for e in sorted_ev if e.get("src_ip")}),
            "mitre_techniques": list({e.get("mitre") for e in sorted_ev if e.get("mitre")}),
            "hosts_compromised": list({e.get("host") for e in sorted_ev if e.get("host")}),
        }

        return {
            "timeline": sorted_ev,
            "phase_timing": phase_timing,
            "phases_detected": phases_present,
            "patient_zero": patient_zero,
            "total_events": len(sorted_ev),
            "dwell_time_minutes": dwell_minutes,
            "attack_start": all_times[0].isoformat() if all_times else "",
            "attack_end": all_times[-1].isoformat() if all_times else "",
            "iocs": iocs
        }
