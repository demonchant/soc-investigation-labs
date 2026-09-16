import re, logging
from collections import defaultdict
logger = logging.getLogger(__name__)

EXT_PAT  = re.compile(r"\.(LOCKED|ENCRYPTED|CRYPTO|CRYPT|WNCRY|CERBER|LOCKY|AES256)$", re.I)
NOTE_PAT = re.compile(r"HOW_TO_DECRYPT|README_DECRYPT|RESTORE_FILES|YOUR_FILES|RANSOM", re.I)
BACKUP_CMDS = [
    (re.compile(r"vssadmin.*(delete|resize)", re.I), "VSS Shadow Copy Deletion"),
    (re.compile(r"bcdedit.*(recoveryenabled|safeboot)", re.I), "Boot Recovery Disabled"),
    (re.compile(r"wbadmin.*(delete|disable)", re.I), "Windows Backup Deletion"),
    (re.compile(r"wmic.*(shadowcopy).*(delete|purge)", re.I), "WMI Shadow Copy Deletion"),
]
KNOWN_C2 = {"185.220.101.47","194.165.16.72","45.142.212.100"}
MITRE = {
    "encrypt": "T1486 - Data Encrypted for Impact",
    "note":    "T1486 - Data Encrypted for Impact (Ransom Note)",
    "backup":  "T1490 - Inhibit System Recovery",
    "persist": "T1547.001 - Registry Run Key Persistence",
    "c2":      "T1041 - Exfiltration Over C2 Channel",
    "spread":  "T1080 - Taint Shared Content / Lateral Spread",
}

class RansomwareEngine:
    def __init__(self): self.alerts = []

    def run(self, events):
        self._encryption(events); self._notes(events)
        self._backup(events); self._persist(events)
        self._c2(events); self._spread(events)
        return self.alerts

    def _a(self, title, sev, host, mitre, ev):
        self.alerts.append({"title":title,"severity":sev,"host":host,"mitre_technique":mitre,"evidence":ev})

    def _encryption(self, events):
        by_host = defaultdict(list)
        for ev in events:
            if ev.get("event_type")=="file_rename" and EXT_PAT.search(ev.get("new_name","")):
                by_host[ev["host"]].append(ev)
        for host, renames in by_host.items():
            if len(renames) >= 3:
                ext = renames[0].get("new_name","").rsplit(".",1)[-1]
                paths = list({r["path"] for r in renames})
                self._a("Mass File Encryption — {} Files Renamed to .{}".format(len(renames),ext),
                    "critical",host,MITRE["encrypt"],
                    {"files_encrypted":len(renames),"extension":ext,
                     "directories":paths,"process":renames[0].get("process","")})

    def _notes(self, events):
        by_host = defaultdict(list)
        for ev in events:
            if ev.get("event_type")=="file_create" and NOTE_PAT.search(ev.get("filename","")):
                by_host[ev["host"]].append(ev)
        for host, notes in by_host.items():
            self._a("Ransom Note Dropped in {} Location(s)".format(len(notes)),
                "critical",host,MITRE["note"],
                {"filename":notes[0].get("filename",""),"locations":[n.get("path","") for n in notes]})

    def _backup(self, events):
        for ev in events:
            if ev.get("event_type")=="process_create":
                cmd = ev.get("cmdline","") or ""
                for pat, desc in BACKUP_CMDS:
                    if pat.search(cmd):
                        self._a("Backup Destruction — "+desc,"critical",ev["host"],MITRE["backup"],
                            {"command":cmd[:120],"process":ev.get("process","")})
                        break

    def _persist(self, events):
        for ev in events:
            if ev.get("event_type")=="registry_set":
                key = ev.get("key","")
                val = ev.get("data","")
                if "CurrentVersion\\Run" in key and any(p in val for p in ["Temp","AppData","ProgramData"]):
                    self._a("Ransomware Persistence via Registry Run Key","critical",ev["host"],MITRE["persist"],
                        {"key":key,"executable":val})

    def _c2(self, events):
        for ev in events:
            if ev.get("event_type")=="network_connect" and ev.get("dst_ip","") in KNOWN_C2:
                self._a("Ransomware C2 Callback — Known Threat Infrastructure","critical",ev["host"],MITRE["c2"],
                    {"dst_ip":ev.get("dst_ip"),"bytes_sent":ev.get("bytes_sent"),"process":ev.get("process","")})

    def _spread(self, events):
        hosts = set()
        for ev in events:
            if ev.get("event_type")=="file_rename" and EXT_PAT.search(ev.get("new_name","")):
                hosts.add(ev["host"])
        if len(hosts) > 1:
            self._a("Ransomware Lateral Spread — {} Hosts Affected".format(len(hosts)),
                "critical","Multiple Hosts",MITRE["spread"],
                {"hosts_affected":list(hosts),"host_count":len(hosts)})
