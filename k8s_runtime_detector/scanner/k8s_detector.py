"""
Kubernetes Runtime Threat Detector
Analyzes K8s audit logs and pod specs for container escape,
privilege abuse, service account lateral movement, and
malicious admission patterns.
"""
import re, logging
from collections import defaultdict
logger = logging.getLogger(__name__)

MITRE = {
    "escape":    "T1611 - Escape to Host",
    "privesc":   "T1610 - Deploy Container (privileged)",
    "lateral":   "T1021 - Remote Services (service account abuse)",
    "persist":   "T1525 - Implant Internal Image",
    "exfil":     "T1552.007 - Unsecured Credentials: Container API",
    "discovery": "T1613 - Container and Resource Discovery",
    "exec":      "T1609 - Container Administration Command",
}

PRIVILEGED_CAPS = {
    "SYS_ADMIN","SYS_PTRACE","SYS_MODULE","NET_ADMIN",
    "SYS_RAWIO","SYS_BOOT","MKNOD","SETFCAP",
}

SENSITIVE_HOST_PATHS = [
    "/etc","/proc","/sys","/root",
    "/var/run/docker.sock","/run/containerd",
    "/var/lib/kubelet","/etc/kubernetes",
]

DANGEROUS_VERBS = {
    "exec":        ("T1609","critical","exec into container — interactive shell"),
    "attach":      ("T1609","critical","attach to running container process"),
    "portforward": ("T1021","high",   "port-forward tunnel into cluster service"),
    "proxy":       ("T1021","high",   "kubectl proxy — API server tunnel"),
}

SECRET_ENV_PATTERN = re.compile(
    r"(password|passwd|secret|api_key|apikey|token|credential|aws_secret|private_key)", re.I)

class K8sRuntimeDetector:
    def __init__(self): self.findings = []

    def detect_all(self, data):
        for pod in data.get("pod_specs", []):
            self._audit_pod(pod)
        for event in data.get("audit_log", []):
            self._audit_event(event)
        self._detect_sa_abuse(data.get("audit_log", []))
        return self.findings

    def _f(self, resource, title, sev, detail, mitre, rec):
        self.findings.append({"resource": resource, "title": title, "severity": sev,
            "detail": detail, "mitre_technique": mitre, "recommendation": rec})

    def _audit_pod(self, pod):
        name = "{}/{}".format(pod.get("namespace","?"), pod.get("name","?"))
        for c in pod.get("containers", []):
            cn = c.get("name","?")
            sc = c.get("security_context", {})

            if sc.get("privileged"):
                self._f(name, "Privileged Container: {}".format(cn), "critical",
                    "Container '{}' in '{}' runs privileged=true — full host kernel access, "
                    "trivial container escape.".format(cn, name),
                    MITRE["escape"],
                    "Remove privileged flag. Use specific capabilities if needed. "
                    "Privileged containers negate all container isolation.")

            if sc.get("run_as_user") == 0 or sc.get("run_as_root"):
                self._f(name, "Container Running as Root: {}".format(cn), "high",
                    "Container '{}' runs as UID 0 — root inside = near-root on host "
                    "if any breakout occurs.".format(cn),
                    MITRE["privesc"],
                    "Set runAsNonRoot: true and runAsUser to non-zero UID.")

            dangerous_caps = [c2 for c2 in sc.get("add_capabilities", [])
                              if c2 in PRIVILEGED_CAPS]
            if dangerous_caps:
                self._f(name, "Dangerous Capabilities: {}".format(cn), "critical",
                    "Container '{}' adds: {}. SYS_ADMIN alone is near-equivalent "
                    "to privileged=true.".format(cn, ", ".join(dangerous_caps)),
                    MITRE["escape"],
                    "Remove dangerous capabilities. Use seccomp/AppArmor instead.")

            if sc.get("allow_privilege_escalation") is not False:
                self._f(name, "Privilege Escalation Not Blocked: {}".format(cn), "medium",
                    "Container '{}' missing allowPrivilegeEscalation=false — "
                    "setuid binaries can escalate to root.".format(cn),
                    MITRE["privesc"],
                    "Add allowPrivilegeEscalation: false to all securityContexts.")

            for ev in c.get("env", []):
                vname = ev.get("name","")
                vval  = ev.get("value","")
                if SECRET_ENV_PATTERN.search(vname) and vval and not ev.get("value_from"):
                    self._f(name, "Hardcoded Secret in Env Var: {}".format(vname), "critical",
                        "Container '{}' has cleartext secret '{}' in environment — "
                        "visible in pod spec, etcd, and process listings.".format(cn, vname),
                        MITRE["exfil"],
                        "Move to Kubernetes Secret + secretKeyRef. Rotate exposed credential.")

        for vol in pod.get("volumes", []):
            hp = vol.get("host_path", {}).get("path", "")
            if hp == "/var/run/docker.sock":
                self._f(name, "Docker Socket Mounted — Trivial Container Escape", "critical",
                    "Pod '{}' mounts the Docker socket. Any container process can spawn "
                    "privileged containers on the host.".format(name),
                    MITRE["escape"],
                    "Remove Docker socket mount. Use Kaniko/Buildah for image builds.")
            elif hp and any(hp.startswith(sp) for sp in SENSITIVE_HOST_PATHS):
                self._f(name, "Sensitive HostPath Mount: {}".format(hp), "high",
                    "Pod '{}' mounts host path '{}' — bypasses container "
                    "filesystem isolation.".format(name, hp),
                    MITRE["escape"],
                    "Replace with PersistentVolume claims. Avoid hostPath in production.")

        if not pod.get("security_context", {}).get("seccomp_profile"):
            self._f(name, "No Seccomp Profile Applied", "medium",
                "Pod '{}' has no seccomp profile — all syscalls permitted, "
                "widening kernel attack surface.".format(name),
                MITRE["escape"],
                "Apply RuntimeDefault seccomp profile at minimum.")

    def _audit_event(self, event):
        verb     = event.get("verb","").lower()
        resource = event.get("resource","").lower()
        ns       = event.get("namespace","default")
        user     = event.get("user",{}).get("username","?")
        obj      = event.get("object_name","")

        if verb in DANGEROUS_VERBS:
            tech, sev, desc = DANGEROUS_VERBS[verb]
            self._f("{}/{}".format(ns, obj),
                "Dangerous API Call: {} on {} by {}".format(verb, resource, user), sev,
                "User '{}' executed {} on '{}' in '{}' — {}.".format(
                    user, verb, obj, ns, desc),
                tech,
                "Verify authorization. Restrict {} via RBAC. "
                "If unexpected — possible credential compromise.".format(verb))

        if resource == "secrets" and verb in ("get","list","watch"):
            self._f(ns, "Secret Read: {} by {}".format(obj or "(all)", user), "high",
                "Principal '{}' read secret '{}' in namespace '{}'.".format(user, obj or "all", ns),
                MITRE["exfil"],
                "Audit why this principal needs secret read. "
                "Rotate if access was unauthorized.")

        if resource == "clusterrolebindings" and verb in ("create","update","patch"):
            self._f(ns, "ClusterRoleBinding Modified by {}".format(user), "critical",
                "User '{}' modified ClusterRoleBinding '{}' — "
                "potential privilege escalation via RBAC.".format(user, obj),
                MITRE["privesc"],
                "Verify this change was authorized. Review new binding scope immediately.")

    def _detect_sa_abuse(self, audit_log):
        sa_data = defaultdict(lambda: {"namespaces":set(),"resources":set(),"events":0})
        for ev in audit_log:
            user = ev.get("user",{}).get("username","")
            if not user.startswith("system:serviceaccount:"):
                continue
            sa_data[user]["namespaces"].add(ev.get("namespace",""))
            sa_data[user]["resources"].add(ev.get("resource",""))
            sa_data[user]["events"] += 1

        for sa, d in sa_data.items():
            if len(d["namespaces"]) > 2:
                self._f(sa, "Service Account Active Across {} Namespaces".format(
                    len(d["namespaces"])), "high",
                    "SA '{}' accessing resources in: {}. "
                    "SAs should be namespace-scoped.".format(sa, ", ".join(d["namespaces"])),
                    MITRE["lateral"],
                    "Replace ClusterRoleBindings with namespace-scoped RoleBindings.")

            if d["events"] > 10 and "secrets" in d["resources"]:
                self._f(sa, "Service Account Harvesting Secrets ({} API calls)".format(
                    d["events"]), "critical",
                    "SA '{}' made {} API calls including secret reads — "
                    "pattern consistent with in-cluster credential harvesting.".format(
                        sa, d["events"]),
                    MITRE["exfil"],
                    "Review pod using this SA. Rotate all secrets in affected namespaces. "
                    "Revoke and recreate the service account token.")
