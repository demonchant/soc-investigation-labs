"""
Threat Hunt Engine - Executes hypothesis-driven threat hunts against log data.
Each hunt implements a structured analytic technique used by real threat hunters.
All detections are purely defensive — identifying attacker activity in enterprise logs.
"""
import re, logging
from collections import defaultdict
logger = logging.getLogger(__name__)


class HuntEngine:
    def __init__(self, hunt_data):
        self.data = hunt_data
        self.results = []

    def run(self, hunts):
        dispatch = {
            "parent_child_anomaly": self._hunt_parent_child,
            "lolbin_download":      self._hunt_lolbin,
            "ntlm_lateral":         self._hunt_ntlm_lateral,
            "masquerade_detection": self._hunt_masquerade,
            "non_browser_outbound": self._hunt_nonbrowser_outbound,
        }
        for hunt in hunts:
            logic = hunt.get("logic")
            handler = dispatch.get(logic)
            if handler:
                findings = handler(hunt)
                self.results.append({
                    "hunt_id":    hunt["id"],
                    "hunt_name":  hunt["name"],
                    "hypothesis": hunt["hypothesis"],
                    "mitre":      hunt["mitre"],
                    "severity":   hunt["severity"],
                    "status":     "HIT" if findings else "MISS",
                    "finding_count": len(findings),
                    "findings":   findings
                })
                status = "HIT (" + str(len(findings)) + " finding(s))" if findings else "MISS — hypothesis not confirmed"
                logger.info(f"  {hunt['id']}: {status}")
            else:
                logger.warning(f"No handler for logic: {logic}")
        return self.results

    # ── Hunt 1: Suspicious parent-child process relationships ──────────────
    def _hunt_parent_child(self, hunt):
        findings = []
        sp = {p.lower() for p in hunt.get("suspicious_parents", [])}
        sc = {c.lower() for c in hunt.get("suspicious_children", [])}
        for proc in self.data.get("process_logs", []):
            parent = proc.get("parent","").lower()
            child  = proc.get("process","").lower()
            if parent in sp and child in sc:
                findings.append({
                    "host":      proc.get("host"),
                    "user":      proc.get("user"),
                    "timestamp": proc.get("timestamp"),
                    "parent":    proc.get("parent"),
                    "child":     proc.get("process"),
                    "cmdline":   proc.get("cmdline","")[:100],
                    "detail":    f"Office/script app '{proc.get('parent')}' spawned '{proc.get('process')}'"
                })
        return findings

    # ── Hunt 2: LOLBin used for file download ─────────────────────────────
    def _hunt_lolbin(self, hunt):
        findings = []
        lolbins   = {l.lower() for l in hunt.get("lolbins", [])}
        patterns  = hunt.get("download_patterns", [])
        for proc in self.data.get("process_logs", []):
            pname = proc.get("process","").lower()
            cmd   = proc.get("cmdline","").lower()
            if pname in lolbins and any(p in cmd for p in patterns):
                findings.append({
                    "host":      proc.get("host"),
                    "user":      proc.get("user"),
                    "timestamp": proc.get("timestamp"),
                    "lolbin":    proc.get("process"),
                    "cmdline":   proc.get("cmdline","")[:120],
                    "detail":    f"LOLBin '{proc.get('process')}' used for remote file download"
                })
        return findings

    # ── Hunt 3: NTLM lateral movement (pass-the-hash) ─────────────────────
    def _hunt_ntlm_lateral(self, hunt):
        findings = []
        threshold = hunt.get("threshold_hosts", 3)
        pkg       = hunt.get("auth_package","NTLM").upper()
        user_hosts = defaultdict(set)
        user_ips   = defaultdict(set)
        for ev in self.data.get("auth_logs", []):
            if ev.get("auth_pkg","").upper() == pkg and ev.get("event") == "logon_success":
                user_hosts[ev["user"]].add(ev.get("host",""))
                user_ips[ev["user"]].add(ev.get("src_ip",""))
        for user, hosts in user_hosts.items():
            if len(hosts) >= threshold:
                findings.append({
                    "user":           user,
                    "hosts_accessed": list(hosts),
                    "unique_hosts":   len(hosts),
                    "src_ips":        list(user_ips[user]),
                    "auth_package":   pkg,
                    "detail":         f"User '{user}' authenticated to {len(hosts)} hosts via {pkg} — possible pass-the-hash"
                })
        return findings

    # ── Hunt 4: Process masquerading ──────────────────────────────────────
    def _hunt_masquerade(self, hunt):
        findings = []
        legit     = {n.lower() for n in hunt.get("legitimate_names", [])}
        sus_paths = hunt.get("suspicious_paths", [])
        for proc in self.data.get("process_logs", []):
            pname = proc.get("process","").lower()
            cmd   = proc.get("cmdline","")
            if pname in legit and any(p.lower() in cmd.lower() for p in sus_paths):
                findings.append({
                    "host":      proc.get("host"),
                    "user":      proc.get("user"),
                    "timestamp": proc.get("timestamp"),
                    "process":   proc.get("process"),
                    "cmdline":   cmd[:120],
                    "detail":    f"Legitimate process name '{proc.get('process')}' running from suspicious path"
                })
        return findings

    # ── Hunt 5: Non-browser outbound network connections ──────────────────
    def _hunt_nonbrowser_outbound(self, hunt):
        findings = []
        sus_procs  = {p.lower() for p in hunt.get("suspicious_processes", [])}
        internal   = ("10.","172.16.","172.17.","172.18.","192.168.")
        for ev in self.data.get("network_logs", []):
            proc    = ev.get("process","").lower()
            dst     = ev.get("dst_ip","")
            is_ext  = not any(dst.startswith(p) for p in internal)
            if proc in sus_procs and is_ext:
                findings.append({
                    "host":      ev.get("host"),
                    "process":   ev.get("process"),
                    "dst_ip":    dst,
                    "dst_port":  ev.get("dst_port"),
                    "bytes":     ev.get("bytes"),
                    "timestamp": ev.get("timestamp"),
                    "detail":    f"Process '{ev.get('process')}' made outbound connection to external IP {dst}"
                })
        return findings
