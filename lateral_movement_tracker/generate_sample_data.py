"""Generate Windows auth event logs showing lateral movement chains."""
import json, random, time
from datetime import datetime, timezone

events = []
base = time.time() - 3600
PROTOCOLS = ["SMB", "RDP", "WMI", "PSEXEC", "WINRM", "SSH"]
HOSTS = ["WS-001", "WS-002", "WS-003", "WS-004", "SRV-DC01", "SRV-FILE01", "SRV-SQL01"]

# === MALICIOUS: Lateral movement chain WS-001 → WS-003 → SRV-FILE01 → SRV-DC01 ===
chain = [("WS-001","WS-003","SMB","jdoe"), ("WS-003","SRV-FILE01","PSEXEC","jdoe"),
         ("SRV-FILE01","SRV-SQL01","WMI","svc_backup"), ("SRV-SQL01","SRV-DC01","WINRM","svc_backup")]
t = base + 100
for src, dst, proto, user in chain:
    t += random.uniform(45, 90)
    events.append({"timestamp": datetime.fromtimestamp(t, tz=timezone.utc).isoformat(),
                   "src_host": src, "dst_host": dst, "username": user,
                   "protocol": proto, "status": "success",
                   "logon_type": "Network", "event_id": 4624, "os": "windows"})

# === MALICIOUS: Second attacker chain ===
chain2 = [("WS-004","WS-002","RDP","admin"), ("WS-002","SRV-FILE01","SMB","admin"),
          ("SRV-FILE01","SRV-DC01","PSEXEC","Administrator")]
t = base + 300
for src, dst, proto, user in chain2:
    t += random.uniform(60, 120)
    events.append({"timestamp": datetime.fromtimestamp(t, tz=timezone.utc).isoformat(),
                   "src_host": src, "dst_host": dst, "username": user,
                   "protocol": proto, "status": "success",
                   "logon_type": "Network", "event_id": 4624, "os": "windows"})

# === BENIGN: Normal admin activity ===
for _ in range(60):
    t = base + random.uniform(0, 3600)
    src, dst = random.sample(HOSTS[:4], 2)
    events.append({"timestamp": datetime.fromtimestamp(t, tz=timezone.utc).isoformat(),
                   "src_host": src, "dst_host": dst,
                   "username": f"employee{random.randint(1,20)}",
                   "protocol": random.choice(["SMB","RDP"]),
                   "status": "success", "logon_type": "Network",
                   "event_id": 4624, "os": "windows"})

# === BENIGN: Failed logins (noise) ===
for _ in range(30):
    t = base + random.uniform(0, 3600)
    src, dst = random.sample(HOSTS, 2)
    events.append({"timestamp": datetime.fromtimestamp(t, tz=timezone.utc).isoformat(),
                   "src_host": src, "dst_host": dst,
                   "username": f"user{random.randint(1,10)}",
                   "protocol": "SMB", "status": "failure",
                   "logon_type": "Network", "event_id": 4625, "os": "windows"})

random.shuffle(events)
with open("sample_auth_events.ndjson", "w") as f:
    for e in events:
        f.write(json.dumps(e) + "\n")
print(f"Generated {len(events)} auth events → sample_auth_events.ndjson")
