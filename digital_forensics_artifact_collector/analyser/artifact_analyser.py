"""
Digital Forensics Artifact Analyser
Analyses collected forensic artifacts from a Windows host to identify
indicators of compromise, malicious persistence mechanisms, suspicious
processes, network connections to threat infrastructure, and timeline
anomalies. Purely defensive — designed for incident response investigators.
"""
import re, logging
from collections import defaultdict

logger = logging.getLogger(__name__)

KNOWN_MALICIOUS_HASHES = {
    "7b774effe4a349c6dd82ad4f4f21d34c": "CobaltStrike Beacon",
    "5d41402abc4b2a76b9719d911017c592": "Unknown PE - suspicious",
    "d41d8cd98f00b204e9800998ecf8427e": "Macro-enabled Office document",
    "96e89a958e49b9e92c8a7e1a0d4e3f2c": "Mimikatz",
}

KNOWN_THREAT_IPS = {
    "185.220.101.47": "Known C2 / Tor exit - LockBit infrastructure",
    "194.165.16.72":  "Known malicious - threat actor infrastructure",
    "45.142.212.100": "Malicious VPS - confirmed attacker use",
}

SUSPICIOUS_PATHS = ["AppData", "Temp", "Downloads", "Public", "ProgramData"]
LEGIT_NAMES      = ["svchost.exe","lsass.exe","csrss.exe","winlogon.exe","services.exe"]
LOLBINS          = ["certutil.exe","bitsadmin.exe","mshta.exe","regsvr32.exe","rundll32.exe"]
TOOL_NAMES       = ["mimikatz","procdump","pwdump","wce.exe","gsecdump","psexec"]

MITRE = {
    "malicious_process":   "T1059 - Command and Scripting Interpreter",
    "lolbin_abuse":        "T1105 - Ingress Tool Transfer via LOLBin",
    "masquerade":          "T1036.005 - Match Legitimate Name/Location",
    "c2_connection":       "T1071 - Application Layer Protocol (C2)",
    "run_key_persist":     "T1547.001 - Registry Run Key Persistence",
    "scheduled_task":      "T1053.005 - Scheduled Task Persistence",
    "known_tool":          "T1003 - Credential Access / Attack Tool",
    "macro_document":      "T1566.001 - Spearphishing: Malicious Attachment",
    "hidden_file":         "T1564.001 - Hidden Files and Directories",
    "c2_ip_file":          "T1105 - File Downloaded from Known C2",
    "high_file_access":    "T1005 - Data from Local System (Collection)",
}


class ArtifactAnalyser:
    def __init__(self):
        self.findings = []

    def analyse(self, artifacts):
        host = artifacts.get("host","unknown")
        logger.info(f"Analysing artifacts from: {host}")

        self._analyse_processes(artifacts.get("running_processes",[]))
        self._analyse_network(artifacts.get("network_connections",[]))
        self._analyse_registry(artifacts.get("registry_run_keys",[]))
        self._analyse_files(artifacts.get("recently_modified_files",[]))
        self._analyse_scheduled_tasks(artifacts.get("scheduled_tasks",[]))
        self._analyse_prefetch(artifacts.get("prefetch_files",[]))
        self._analyse_event_logs(artifacts.get("event_logs_summary",[]))

        logger.info(f"Analysis complete. {len(self.findings)} finding(s).")
        return self.findings

    def _finding(self, category, title, severity, detail, mitre, evidence=None):
        self.findings.append({
            "category":   category,
            "title":      title,
            "severity":   severity,
            "detail":     detail,
            "mitre":      mitre,
            "evidence":   evidence or {}
        })

    # ── Process analysis ─────────────────────────────────────────────────
    def _analyse_processes(self, procs):
        for p in procs:
            name = p.get("name","").lower()
            path = p.get("path","")
            cmd  = p.get("cmdline","")
            user = p.get("user","")

            # LOLBin with download pattern
            if any(lb in name for lb in LOLBINS):
                if any(kw in cmd.lower() for kw in ["urlcache","split","-f http","downloadfile"]):
                    self._finding("process", "LOLBin Used for Remote File Download",
                        "critical", f"{name} used to download from remote URL.",
                        MITRE["lolbin_abuse"],
                        {"process":name,"user":user,"cmdline":cmd[:120],"pid":p.get("pid")})

            # Masquerading — legit name, suspicious path
            if name in LEGIT_NAMES and any(sp.lower() in path.lower() for sp in SUSPICIOUS_PATHS):
                self._finding("process", "Process Masquerading in User-Writable Path",
                    "critical", f"'{name}' running from suspicious path: {path}",
                    MITRE["masquerade"],
                    {"process":name,"path":path,"user":user,"pid":p.get("pid")})

            # Known offensive tools
            if any(tool in name.lower() or tool in cmd.lower() for tool in TOOL_NAMES):
                self._finding("process", "Known Attack Tool Detected in Process List",
                    "critical", f"Tool '{name}' is known offensive security software.",
                    MITRE["known_tool"],
                    {"process":name,"cmdline":cmd[:120],"user":user,"pid":p.get("pid")})

            # Encoded PowerShell
            if "powershell" in name and re.search(r"-[Ee]nc(odedCommand)?", cmd):
                self._finding("process", "PowerShell Encoded Command Execution",
                    "critical", "PowerShell launched with -EncodedCommand — payload obfuscated.",
                    MITRE["malicious_process"],
                    {"process":name,"cmdline":cmd[:120],"user":user,"pid":p.get("pid")})

    # ── Network connection analysis ───────────────────────────────────────
    def _analyse_network(self, connections):
        for conn in connections:
            remote_ip = conn.get("remote_ip","")
            proc      = conn.get("process","")
            if remote_ip in KNOWN_THREAT_IPS:
                self._finding("network", "Active Connection to Known Threat Infrastructure",
                    "critical",
                    f"Process '{proc}' has ESTABLISHED connection to {remote_ip} ({KNOWN_THREAT_IPS[remote_ip]}).",
                    MITRE["c2_connection"],
                    {"process":proc,"remote_ip":remote_ip,"remote_port":conn.get("remote_port"),
                     "state":conn.get("state"),"pid":conn.get("pid")})

    # ── Registry run key analysis ─────────────────────────────────────────
    def _analyse_registry(self, run_keys):
        legit_run_values = {"OneDriveSync","SecurityHealth","OneDrive"}
        for key in run_keys:
            val_name = key.get("value_name","")
            val_data = key.get("value_data","")
            if val_name not in legit_run_values:
                suspicious_path = any(sp.lower() in val_data.lower() for sp in SUSPICIOUS_PATHS)
                sev = "critical" if suspicious_path else "high"
                self._finding("persistence", "Suspicious Registry Run Key",
                    sev,
                    f"Run key '{val_name}' → '{val_data}' — not in known-good baseline.",
                    MITRE["run_key_persist"],
                    {"hive":key.get("hive"),"key":key.get("key"),
                     "value_name":val_name,"value_data":val_data})

    # ── Recently modified file analysis ──────────────────────────────────
    def _analyse_files(self, files):
        for f in files:
            path  = f.get("path","")
            md5   = f.get("hash_md5","")
            attrs = f.get("attributes","")

            # Known malicious hash
            if md5 in KNOWN_MALICIOUS_HASHES:
                self._finding("file", "Known Malicious File Hash",
                    "critical",
                    f"File '{path}' matches known malware hash: {KNOWN_MALICIOUS_HASHES[md5]}.",
                    MITRE["c2_ip_file"],
                    {"path":path,"md5":md5,"family":KNOWN_MALICIOUS_HASHES[md5],
                     "size_kb":f.get("size_kb"),"modified":f.get("modified")})

            # Hidden + system attributes
            if "HIDDEN" in attrs and any(sp.lower() in path.lower() for sp in SUSPICIOUS_PATHS):
                self._finding("file", "Hidden File in User-Writable Location",
                    "high",
                    f"File '{path}' has HIDDEN attribute — common malware staging technique.",
                    MITRE["hidden_file"],
                    {"path":path,"attributes":attrs,"md5":md5,"modified":f.get("modified")})

    # ── Scheduled task analysis ───────────────────────────────────────────
    def _analyse_scheduled_tasks(self, tasks):
        legit_creators = {"SYSTEM","NT AUTHORITY\\SYSTEM"}
        for task in tasks:
            action  = task.get("action","")
            created = task.get("created_by","")
            trigger = task.get("trigger","")
            if created not in legit_creators and any(sp.lower() in action.lower() for sp in SUSPICIOUS_PATHS):
                self._finding("persistence", "Suspicious Scheduled Task Created by User",
                    "critical",
                    f"Task '{task.get('name')}' created by '{created}' runs from suspicious path.",
                    MITRE["scheduled_task"],
                    {"task_name":task.get("name"),"action":action,
                     "trigger":trigger,"created_by":created})

    # ── Prefetch file analysis ────────────────────────────────────────────
    def _analyse_prefetch(self, prefetch):
        for pf in prefetch:
            exe  = pf.get("executable","").lower()
            refs = pf.get("path_refs",[])
            if any(tool in exe for tool in ["mimikatz","procdump","psexec","wce"]):
                self._finding("execution_trace", "Attack Tool Execution in Prefetch",
                    "critical",
                    f"Prefetch evidence: '{pf.get('executable')}' ran {pf.get('run_count')} time(s). Last: {pf.get('last_run')}.",
                    MITRE["known_tool"],
                    {"executable":pf.get("executable"),"run_count":pf.get("run_count"),
                     "last_run":pf.get("last_run"),"path_refs":refs})
            if "svchost" in exe and any("temp" in r.lower() or "appdata" in r.lower() for r in refs):
                self._finding("execution_trace", "Masqueraded Svchost.exe Executed (Prefetch)",
                    "critical",
                    f"Prefetch shows svchost.exe ran from user-writable path.",
                    MITRE["masquerade"],
                    {"executable":pf.get("executable"),"path_refs":refs,
                     "run_count":pf.get("run_count"),"last_run":pf.get("last_run")})

    # ── Event log summary analysis ────────────────────────────────────────
    def _analyse_event_logs(self, events):
        for ev in events:
            if ev.get("event_id") == 4625 and ev.get("count",0) > 100:
                self._finding("event_log", "High Volume of Failed Logon Events",
                    "high",
                    f"{ev['count']} failed logon events (Event ID 4625) — possible brute force or credential spray.",
                    "T1110 - Brute Force",
                    {"event_id":4625,"count":ev["count"]})
            if ev.get("event_id") == 4663 and ev.get("count",0) > 1000:
                self._finding("event_log", "Abnormally High File Access Volume",
                    "high",
                    f"{ev['count']} file access events — possible bulk collection or ransomware staging.",
                    MITRE["high_file_access"],
                    {"event_id":4663,"count":ev["count"]})
