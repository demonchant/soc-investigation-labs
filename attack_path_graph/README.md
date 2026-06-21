# Attack Path Graph Engine

Models an Active Directory environment as a directed graph of computers, users, groups, and sessions — then runs BFS pathfinding to find every route a compromised low-privilege user could take to reach Domain Admin. BloodHound-style attack path analysis built from scratch to identify and prioritize the highest-risk privilege escalation chains.

```bash
python main.py
```

SOC L2 Analyst | github.com/demonchant
