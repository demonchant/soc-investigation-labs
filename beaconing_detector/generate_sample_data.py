"""Generates realistic sample netflow data including beaconing C2 traffic."""
import json, random, time
from datetime import datetime, timezone

def generate_data():
    events = []
    base_time = time.time() - 7200  # 2 hours ago

    # === MALICIOUS: Cobalt Strike beacon every ~60s with ±15% jitter ===
    cs_times = []
    t = base_time
    for _ in range(35):
        jitter = random.uniform(-0.15, 0.15)
        t += 60 * (1 + jitter)
        cs_times.append(t)
        events.append({
            "timestamp": datetime.fromtimestamp(t, tz=timezone.utc).isoformat(),
            "src_ip": "192.168.1.105",
            "dst_ip": "185.220.101.47",
            "dst_port": 443,
            "dst_host": "evil-c2.example.com",
            "bytes_out": random.randint(200, 800),
            "bytes_in": random.randint(50, 200),
            "protocol": "HTTPS"
        })

    # === MALICIOUS: Metasploit Meterpreter every ~120s ===
    t = base_time
    for _ in range(28):
        jitter = random.uniform(-0.10, 0.10)
        t += 120 * (1 + jitter)
        events.append({
            "timestamp": datetime.fromtimestamp(t, tz=timezone.utc).isoformat(),
            "src_ip": "10.0.0.88",
            "dst_ip": "91.108.4.200",
            "dst_port": 4444,
            "dst_host": "",
            "bytes_out": random.randint(100, 400),
            "bytes_in": random.randint(30, 150),
            "protocol": "TCP"
        })

    # === MALICIOUS: DNS beacon every ~30s ===
    t = base_time
    for _ in range(45):
        jitter = random.uniform(-0.05, 0.05)
        t += 30 * (1 + jitter)
        events.append({
            "timestamp": datetime.fromtimestamp(t, tz=timezone.utc).isoformat(),
            "src_ip": "10.0.0.55",
            "dst_ip": "8.8.8.8",
            "dst_port": 53,
            "dst_host": "dns.google",
            "bytes_out": random.randint(60, 120),
            "bytes_in": random.randint(60, 120),
            "protocol": "DNS"
        })

    # === BENIGN: Windows Update (irregular, allowlisted) ===
    t = base_time
    for _ in range(8):
        t += random.uniform(300, 900)
        events.append({
            "timestamp": datetime.fromtimestamp(t, tz=timezone.utc).isoformat(),
            "src_ip": "192.168.1.200",
            "dst_ip": "13.107.4.50",
            "dst_port": 443,
            "dst_host": "updates.microsoft.com",
            "bytes_out": random.randint(500, 50000),
            "bytes_in": random.randint(10000, 500000),
            "protocol": "HTTPS"
        })

    # === BENIGN: Normal web browsing (random intervals) ===
    for _ in range(60):
        t = base_time + random.uniform(0, 7200)
        events.append({
            "timestamp": datetime.fromtimestamp(t, tz=timezone.utc).isoformat(),
            "src_ip": f"192.168.1.{random.randint(10, 50)}",
            "dst_ip": f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
            "dst_port": random.choice([80, 443, 8080]),
            "dst_host": random.choice(["google.com", "github.com", "slack.com", "youtube.com"]),
            "bytes_out": random.randint(200, 5000),
            "bytes_in": random.randint(1000, 100000),
            "protocol": "HTTPS"
        })

    random.shuffle(events)

    with open("sample_netflow.ndjson", "w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")

    print(f"Generated {len(events)} events → sample_netflow.ndjson")

if __name__ == "__main__":
    generate_data()
