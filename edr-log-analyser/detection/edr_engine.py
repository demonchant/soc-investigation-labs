"""
EDR Detection Engine — Detects endpoint threats from Windows Event Log + Sysmon data.
All string fields are safely coerced — handles None values from optional event fields.
"""
import re, logging
from collections import defaultdict

logger = logging.getLogger(__name__)

MITRE = {
    "ps_encoded":   "T1059.001 - PowerShell Encoded Command",
    "cred_dump":    "T1003.001 - LSASS Credential Dumping",
    "run_key":      "T1547.001 - Registry Run Key Persistence",
    "certutil_dl":  "T1105 - Ingress Tool Transfer via Certutil LOLBin",
    "vss_delete":   "T1490 - Inhibit System Recovery (VSS Deletion)",
    "wmic_lateral": "T1021.003 - WMIC Remote Process Execution",
    "macro_spawn":  "T1566.001 - Phishing: Office Macro Child Process",
    "spray":        "T1110.003 - Password Spraying",
    "masquerade":   "T1036.005 - Process Masquerading",
}

CRED_TOOLS   = re.compile(r"mimikatz|procdump|lsass|pwdump|wce\\.exe|gsecdump", re.I)
MASQ_PATHS   = re.compile(r"(AppData|Temp|Downloads|Public).*?(svchost|lsass|csrss|winlogon)", re.I)
OFFICE_PROCS = {"winword.exe","excel.exe","powerpnt.exe","outlook.exe","mshta.exe","wscript.exe"}
SHELL_PROCS  = {"powershell.exe","cmd.exe","wscript.exe","mshta.exe","rundll32.exe"}


def _s(val):
    """Safe string: coerce None/non-string to empty string."""
    return str(val) if val is not None else ""


class EDREngine:
    def __init__(self):
        self.alerts = []

    def run(self, events):
        self._ps_encoded(events)
        self._cred_dumping(events)
        self._run_key_persistence(events)
        self._certutil_download(events)
        self._vss_deletion(events)
        self._wmic_lateral(events)
        self._office_macro_spawn(events)
        self._password_spray(events)
        self._masquerading(events)
        logger.info("EDR detection complete. " + str(len(self.alerts)) + " alert(s).")
        return self.alerts

    def _alert(self, title, severity, host, user, mitre, evidence):
        self.alerts.append({
            "title": title, "severity": severity,
            "host": host, "user": user,
            "mitre_technique": mitre, "evidence": evidence
        })

    def _ps_encoded(self, events):
        for ev in events:
            proc = _s(ev.get("process")).lower()
            cmd  = _s(ev.get("cmdline"))
            if proc == "powershell.exe" and re.search(r"-[Ee]nc(odedCommand)?", cmd):
                self._alert("PowerShell Encoded Command Execution", "high",
                    ev["host"], _s(ev.get("user")), MITRE["ps_encoded"],
                    {"cmdline": cmd[:120], "parent": _s(ev.get("parent_process"))})

    def _cred_dumping(self, events):
        for ev in events:
            proc = _s(ev.get("process"))
            cmd  = _s(ev.get("cmdline"))
            path = _s(ev.get("file_path"))
            if CRED_TOOLS.search(proc) or CRED_TOOLS.search(cmd) or CRED_TOOLS.search(path):
                self._alert("Credential Dumping Tool Detected", "critical",
                    ev["host"], _s(ev.get("user")), MITRE["cred_dump"],
                    {"process": proc, "cmdline": cmd[:120], "file_path": path})

    def _run_key_persistence(self, events):
        for ev in events:
            rk  = _s(ev.get("registry_key"))
            cmd = _s(ev.get("cmdline"))
            if "CurrentVersion\\Run" in rk or ("reg add" in cmd.lower() and "\\Run" in cmd):
                self._alert("Registry Run Key Persistence Established", "high",
                    ev["host"], _s(ev.get("user")), MITRE["run_key"],
                    {"registry_key": rk, "cmdline": cmd[:120]})

    def _certutil_download(self, events):
        for ev in events:
            proc = _s(ev.get("process"))
            cmd  = _s(ev.get("cmdline"))
            if "certutil" in proc.lower() and re.search(r"-urlcache|-split|-f\s+http", cmd, re.I):
                self._alert("Certutil LOLBin File Download", "critical",
                    ev["host"], _s(ev.get("user")), MITRE["certutil_dl"],
                    {"cmdline": cmd[:120], "parent": _s(ev.get("parent_process"))})

    def _vss_deletion(self, events):
        for ev in events:
            cmd = _s(ev.get("cmdline"))
            if re.search(r"vssadmin.+delete|wmic.+shadowcopy.+delete|bcdedit.+recoveryenabled", cmd, re.I):
                self._alert("VSS Shadow Copy Deletion - Ransomware Indicator", "critical",
                    ev["host"], _s(ev.get("user")), MITRE["vss_delete"],
                    {"cmdline": cmd[:120], "process": _s(ev.get("process"))})

    def _wmic_lateral(self, events):
        for ev in events:
            proc = _s(ev.get("process"))
            cmd  = _s(ev.get("cmdline"))
            if "wmic.exe" in proc.lower() and re.search(r"/node:.+process.+call.+create", cmd, re.I):
                self._alert("WMIC Remote Process Execution - Lateral Movement", "high",
                    ev["host"], _s(ev.get("user")), MITRE["wmic_lateral"],
                    {"cmdline": cmd[:120], "parent": _s(ev.get("parent_process"))})

    def _office_macro_spawn(self, events):
        for ev in events:
            parent = _s(ev.get("parent_process")).lower()
            proc   = _s(ev.get("process")).lower()
            if parent in OFFICE_PROCS and proc in SHELL_PROCS:
                self._alert("Office Application Spawned Suspicious Child Process", "critical",
                    ev["host"], _s(ev.get("user")), MITRE["macro_spawn"],
                    {"parent": _s(ev.get("parent_process")), "child": _s(ev.get("process")),
                     "cmdline": _s(ev.get("cmdline"))[:120]})

    def _password_spray(self, events):
        fails = defaultdict(set)
        for ev in events:
            if ev["event_type"] == "logon_fail":
                src = _s(ev.get("src_ip"))
                if src:
                    fails[src].add(ev["host"])
        for ip, hosts in fails.items():
            if len(hosts) >= 3:
                self._alert("Password Spray Attack Detected", "high",
                    "Multiple (" + str(len(hosts)) + " hosts)", "", MITRE["spray"],
                    {"src_ip": ip, "hosts_targeted": list(hosts), "count": len(hosts)})

    def _masquerading(self, events):
        for ev in events:
            path = _s(ev.get("file_path"))
            if MASQ_PATHS.search(path):
                self._alert("Process Masquerading in User-Writable Path", "high",
                    ev["host"], _s(ev.get("user")), MITRE["masquerade"],
                    {"file_path": path, "process": _s(ev.get("process"))})
