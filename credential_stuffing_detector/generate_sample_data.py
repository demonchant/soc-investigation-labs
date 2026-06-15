"""Generates realistic auth logs with credential stuffing, spraying, and normal traffic."""
import json, random, time
from datetime import datetime, timezone

UAS_LEGIT = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
             "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
             "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)"]
UAS_BOT = [f"python-requests/2.{random.randint(20,30)}.0" for _ in range(5)] + \
          ["Go-http-client/1.1", "curl/7.85.0", "Wget/1.21"]
USERNAMES_STUFFING = [f"user{i}@company.com" for i in range(200)]
USERNAMES_SPRAY = ["admin@company.com", "ceo@company.com", "finance@company.com",
                   "hr@company.com", "it@company.com", "dev@company.com"]

events = []
base = time.time() - 3600

# Credential stuffing attacker
t = base
for i in range(300):
    t += random.uniform(0.2, 1.5)
    user = random.choice(USERNAMES_STUFFING)
    hit = random.random() < 0.03  # 3% success rate
    events.append({"timestamp": datetime.fromtimestamp(t, tz=timezone.utc).isoformat(),
                   "ip": "45.33.32.156", "username": user,
                   "status": "success" if hit else "failure",
                   "user_agent": random.choice(UAS_BOT),
                   "endpoint": "/api/v1/auth/login"})

# Password spray attacker
t = base + 100
for cycle in range(15):
    for user in USERNAMES_SPRAY:
        t += random.uniform(2, 8)
        events.append({"timestamp": datetime.fromtimestamp(t, tz=timezone.utc).isoformat(),
                       "ip": "103.21.244.0", "username": user,
                       "status": "failure", "user_agent": "python-requests/2.28.0",
                       "endpoint": "/login"})

# Brute force single account
t = base + 200
for _ in range(80):
    t += random.uniform(0.5, 3)
    events.append({"timestamp": datetime.fromtimestamp(t, tz=timezone.utc).isoformat(),
                   "ip": "198.51.100.22", "username": "admin@company.com",
                   "status": "failure", "user_agent": "Hydra v9.4",
                   "endpoint": "/admin/login"})

# Legitimate users
for _ in range(150):
    t = base + random.uniform(0, 3600)
    events.append({"timestamp": datetime.fromtimestamp(t, tz=timezone.utc).isoformat(),
                   "ip": f"192.168.{random.randint(1,5)}.{random.randint(1,254)}",
                   "username": f"employee{random.randint(1,50)}@company.com",
                   "status": random.choice(["success", "success", "success", "failure"]),
                   "user_agent": random.choice(UAS_LEGIT),
                   "endpoint": "/login"})

random.shuffle(events)
with open("sample_auth.ndjson", "w") as f:
    for e in events:
        f.write(json.dumps(e) + "\n")
print(f"Generated {len(events)} auth events → sample_auth.ndjson")
