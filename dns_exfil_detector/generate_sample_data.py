"""Generate DNS logs with real exfiltration patterns (iodine/dnscat2 style)."""
import json, random, string, time, base64
from datetime import datetime, timezone

def b32_subdomain(length=45):
    """Simulate base32-encoded data in DNS subdomain (iodine style)."""
    chars = "abcdefghijklmnopqrstuvwxyz234567"
    return "".join(random.choices(chars, k=length))

def random_subdomain(length=8):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))

events = []
base = time.time() - 3600

# DNS Tunnel (iodine): base32 subdomains, high entropy, NXDOMAIN
t = base
for _ in range(120):
    t += random.uniform(0.5, 3)
    sub1 = b32_subdomain(random.randint(35, 55))
    sub2 = b32_subdomain(random.randint(10, 20))
    events.append({"timestamp": datetime.fromtimestamp(t, tz=timezone.utc).isoformat(),
                   "src_ip": "10.0.0.55", "query": f"{sub1}.{sub2}.tunnel.evil-corp.net",
                   "qtype": random.choice(["A", "TXT", "NULL"]),
                   "rcode": random.choice(["NOERROR", "NXDOMAIN", "NXDOMAIN"])})

# dnscat2 style: shorter random subdomains, many NXDOMAIN
t = base + 50
for _ in range(80):
    t += random.uniform(1, 5)
    sub = "".join(random.choices(string.hexdigits.lower(), k=random.randint(20, 40)))
    events.append({"timestamp": datetime.fromtimestamp(t, tz=timezone.utc).isoformat(),
                   "src_ip": "192.168.1.88", "query": f"{sub}.c2channel.xyz",
                   "qtype": "TXT", "rcode": random.choice(["NOERROR", "NXDOMAIN"])})

# Normal DNS traffic
for _ in range(200):
    t = base + random.uniform(0, 3600)
    domain = random.choice(["google.com", "microsoft.com", "github.com",
                             "cloudflare.com", "amazonaws.com", "office.com"])
    sub = random.choice(["www", "mail", "api", "cdn", "static", ""])
    query = f"{sub}.{domain}" if sub else domain
    events.append({"timestamp": datetime.fromtimestamp(t, tz=timezone.utc).isoformat(),
                   "src_ip": f"192.168.{random.randint(1,5)}.{random.randint(1,254)}",
                   "query": query, "qtype": "A", "rcode": "NOERROR"})

random.shuffle(events)
with open("sample_dns.ndjson", "w") as f:
    for e in events:
        f.write(json.dumps(e) + "\n")
print(f"Generated {len(events)} DNS events → sample_dns.ndjson")
