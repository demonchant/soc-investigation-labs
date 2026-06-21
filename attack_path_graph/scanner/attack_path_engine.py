import logging
from collections import defaultdict, deque
logger = logging.getLogger(__name__)

MITRE = {
    "path":      "T1078 - Valid Accounts (privilege escalation path)",
    "admin_to":  "T1021 - Remote Services (AdminTo edge)",
    "memberof":  "T1078.002 - Domain Accounts (group nesting)",
    "hassession":"T1003 - OS Credential Dumping (session harvesting)",
    "dcsync":    "T1003.006 - DCSync",
    "kerberoast":"T1558.003 - Kerberoasting",
    "genericall":"T1098 - Account Manipulation (GenericAll/WriteDACL abuse)",
}

# Edge types and their exploitation weight (lower = easier for attacker to exploit)
EDGE_WEIGHTS = {
    "AdminTo":      1,   # already have admin rights — direct
    "HasSession":   2,   # can dump creds from session
    "MemberOf":     1,   # group nesting is free
    "GenericAll":   2,   # full object control — can reset password etc
    "WriteDacl":    2,   # can grant self further rights
    "ForceChangePassword": 2,
    "CanRDP":       3,   # can log in, then needs further escalation
    "AddMember":    2,   # can add self/others to group
    "Owns":         2,
}

TIER0_GROUPS = {"Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators"}

class AttackPathEngine:
    def __init__(self):
        self.findings = []
        self.edges = defaultdict(list)   # node -> [(target, edge_type)]
        self.node_types = {}

    def analyze_all(self, data):
        self._build_graph(data)
        self._find_paths_to_tier0(data)
        self._flag_high_value_edges(data)
        self._flag_kerberoastable_admins(data)
        return self.findings

    def _f(self, title, sev, detail, mitre, rec, path=None):
        self.findings.append({"title": title, "severity": sev, "detail": detail,
            "mitre_technique": mitre, "recommendation": rec, "path": path or []})

    def _build_graph(self, data):
        for node in data.get("nodes", []):
            self.node_types[node["name"]] = node["type"]
        for edge in data.get("edges", []):
            self.edges[edge["source"]].append((edge["target"], edge["edge_type"]))

    def _bfs_shortest_path(self, start, targets):
        """Returns shortest weighted path from start to any node in targets, or None."""
        # Dijkstra-lite since weights are small positive ints
        import heapq
        pq = [(0, start, [start])]
        visited = {}
        while pq:
            cost, node, path = heapq.heappop(pq)
            if node in targets and len(path) > 1:
                return cost, path
            if node in visited and visited[node] <= cost:
                continue
            visited[node] = cost
            for neighbor, edge_type in self.edges.get(node, []):
                weight = EDGE_WEIGHTS.get(edge_type, 5)
                new_path = path + [neighbor]
                edge_path = self._annotate(new_path)
                heapq.heappush(pq, (cost + weight, neighbor, new_path))
        return None, None

    def _annotate(self, path):
        return path

    def _edge_type_between(self, a, b):
        for target, etype in self.edges.get(a, []):
            if target == b:
                return etype
        return "?"

    def _find_paths_to_tier0(self, data):
        tier0_nodes = {n["name"] for n in data.get("nodes", [])
                       if n["type"] == "group" and n["name"] in TIER0_GROUPS}
        if not tier0_nodes:
            return

        start_nodes = [n["name"] for n in data.get("nodes", [])
                       if n["type"] == "user" and not n.get("is_privileged", False)]

        for start in start_nodes:
            cost, path = self._bfs_shortest_path(start, tier0_nodes)
            if path:
                edge_chain = []
                for i in range(len(path)-1):
                    etype = self._edge_type_between(path[i], path[i+1])
                    edge_chain.append("{} --[{}]--> {}".format(path[i], etype, path[i+1]))

                hop_count = len(path) - 1
                sev = "critical" if hop_count <= 2 else "high" if hop_count <= 4 else "medium"

                self._f(
                    "Attack Path Found: {} → {} ({} hops)".format(start, path[-1], hop_count),
                    sev,
                    "Shortest path from low-privilege user '{}' to Tier-0 group '{}':\n       {}".format(
                        start, path[-1], "\n       ".join(edge_chain)),
                    MITRE["path"],
                    "{} If this user's credentials are phished, attacker reaches Domain Admin "
                    "in {} step(s). Break this chain at the cheapest edge to disrupt.".format(
                        "CRITICAL — direct path." if hop_count <= 2 else "Prioritize remediation.",
                        hop_count),
                    path
                )

    def _flag_high_value_edges(self, data):
        """Flag specific dangerous edge types regardless of full path."""
        edge_counts = defaultdict(list)
        for edge in data.get("edges", []):
            edge_counts[edge["edge_type"]].append((edge["source"], edge["target"]))

        if "GenericAll" in edge_counts:
            for src, tgt in edge_counts["GenericAll"]:
                if self.node_types.get(tgt) in ("computer", "group") or tgt in TIER0_GROUPS:
                    self._f("Dangerous ACL: GenericAll on High-Value Object",
                        "critical",
                        "Principal '{}' has GenericAll (full control) over '{}'. This grants "
                        "password reset, group membership changes, or full object takeover.".format(src, tgt),
                        MITRE["genericall"],
                        "Audit why '{}' has this permission. Remove if not operationally required. "
                        "This is frequently an unintended/legacy delegation.".format(src))

        if "HasSession" in edge_counts:
            session_targets = defaultdict(list)
            for src, tgt in edge_counts["HasSession"]:
                session_targets[tgt].append(src)
            for computer, users in session_targets.items():
                privileged_sessions = [u for u in users if data_user_is_privileged(data, u)]
                if privileged_sessions:
                    self._f("Privileged Session Exposure on {}".format(computer),
                        "high",
                        "Privileged account(s) {} have active/cached sessions on '{}'. "
                        "Any local compromise of this host enables credential theft (Mimikatz) "
                        "against these accounts.".format(", ".join(privileged_sessions), computer),
                        MITRE["hassession"],
                        "Enforce credential guard / restricted admin mode. Avoid logging in "
                        "privileged accounts to non-Tier-0 hosts.")

    def _flag_kerberoastable_admins(self, data):
        for node in data.get("nodes", []):
            if node["type"] == "user" and node.get("has_spn") and node.get("is_privileged"):
                self._f("Kerberoastable Privileged Account: {}".format(node["name"]),
                    "critical",
                    "User '{}' is privileged AND has a registered SPN — Kerberoasting this "
                    "account yields a crackable ticket for a high-value account directly.".format(
                        node["name"]),
                    MITRE["kerberoast"],
                    "Remove SPN from this account if possible, or migrate the service to a "
                    "Group Managed Service Account (gMSA). This is one of the highest-value "
                    "single fixes available.")


def data_user_is_privileged(data, username):
    for n in data.get("nodes", []):
        if n["name"] == username and n["type"] == "user":
            return n.get("is_privileged", False)
    return False
