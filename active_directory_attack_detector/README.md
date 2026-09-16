# Active Directory Attack Detector

> Detects the most common Active Directory attack techniques used in real-world intrusions — Kerberoasting, DCSync, AS-REP Roasting, Golden Ticket usage, privilege escalation via group membership, Kerberos password spraying, and backdoor account creation.

---

## Detections

| Attack | Event ID | MITRE | Signal |
|---|---|---|---|
| Kerberoasting | 4769 | T1558.003 | RC4 (0x17) encryption + ≥3 SPN requests |
| DCSync | 4662 | T1003.006 | Replication GUIDs from non-DC host |
| AS-REP Roasting | 4768 | T1558.004 | Pre-auth type 0 (disabled) |
| Golden Ticket | 4624 | T1558.001 | Ticket lifetime > 100 hours |
| Privilege Escalation | 4728 | T1078+T1098 | User added to Domain Admins |
| Password Spray | 4771 | T1110.003 | Same IP → ≥5 Kerberos preauth failures |
| Backdoor Account | 4720 | T1136.002 | New domain account created |

---

## Quick Start

```bash
python main.py
```

---

## Author

SOC L2 Analyst | github.com/demonchant
