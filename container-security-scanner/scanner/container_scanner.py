import re, logging
logger = logging.getLogger(__name__)

MITRE = {
    "priv":    "T1611 - Escape to Host (privileged container)",
    "root":    "T1068 - Exploitation for Privilege Escalation",
    "hostnet": "T1049 - System Network Connections Discovery",
    "socket":  "T1611 - Escape to Host (Docker socket mount)",
    "mount":   "T1611 - Escape to Host (host filesystem)",
    "secret":  "T1552.007 - Unsecured Credentials: Container API",
    "caps":    "T1548.001 - Setuid/Setgid (dangerous capabilities)",
    "vuln":    "T1190 - Exploit Public-Facing Application (unpatched)",
    "seccomp": "T1055 - Process Injection (no syscall restrictions)",
    "ssh":     "T1021.004 - Remote Services: SSH",
}

DANGEROUS_CAPS = {
    "SYS_ADMIN":   "Full system administration — near-root on host",
    "SYS_PTRACE":  "Can attach to any process and read its memory",
    "NET_ADMIN":   "Can modify network interfaces and routing",
    "DAC_OVERRIDE":"Bypasses file permission checks",
    "SYS_MODULE":  "Can load kernel modules — full kernel access",
}

SENSITIVE_MOUNTS = {
    "/var/run/docker.sock": ("Docker socket — grants full Docker daemon control", "critical"),
    "/etc":                 ("/etc directory — system config including shadow", "high"),
    "/proc":                ("/proc filesystem — process info and kernel params", "high"),
    "/":                    ("Full host root filesystem mounted", "critical"),
}

SECRET_PAT = re.compile(r"password|passwd|secret|api_key|token|key", re.I)

class ContainerScanner:
    def __init__(self): self.findings = []

    def scan_all(self, containers):
        for c in containers: self._scan(c)
        return self.findings

    def _f(self, cid, svc, title, sev, detail, mitre, rec):
        self.findings.append({"container_id":cid,"service":svc,"title":title,
            "severity":sev,"detail":detail,"mitre_technique":mitre,"recommendation":rec})

    def _scan(self, c):
        cid = c["container_id"]; svc = c.get("service", cid)

        if c.get("privileged_mode"):
            self._f(cid,svc,"Container Running in Privileged Mode","critical",
                "Privileged mode grants near-complete host kernel access.",MITRE["priv"],
                "Remove --privileged. Grant only specific required capabilities.")

        if c.get("running_as_root"):
            self._f(cid,svc,"Container Process Running as Root (UID 0)","high",
                "Running as root means container escape = immediate host root.",MITRE["root"],
                "Add USER directive in Dockerfile. Use non-root UID (e.g. USER 1001).")

        if c.get("network_mode") == "host":
            self._f(cid,svc,"Container Using Host Network Mode","high",
                "Host network bypasses network isolation.",MITRE["hostnet"],
                "Use bridge or overlay networking. Expose only required ports.")

        for vol in c.get("volumes",[]):
            host_path = vol.split(":")[0]
            for sp, (desc, sev) in SENSITIVE_MOUNTS.items():
                if host_path == sp or host_path.startswith(sp):
                    mitre_key = "socket" if "docker.sock" in host_path else "mount"
                    self._f(cid,svc,"Sensitive Host Path Mounted: {}".format(host_path),sev,
                        "Volume '{}' — {}".format(vol,desc),MITRE[mitre_key],
                        "Remove this volume mount. Use named volumes instead.")
                    break

        env_vars = c.get("environment_vars",{})
        for key, value in env_vars.items():
            if SECRET_PAT.search(key) and value and len(value) > 3:
                self._f(cid,svc,"Potential Secret in Environment Variable: {}".format(key),"critical",
                    "Env var '{}' appears to contain a hardcoded secret.".format(key),MITRE["secret"],
                    "Use Docker secrets or Vault. Never hardcode secrets in env vars.")
            elif SECRET_PAT.search(key) and value == "":
                self._f(cid,svc,"Empty Credential in Environment Variable: {}".format(key),"critical",
                    "Service '{}' has empty credential configured.".format(svc),MITRE["secret"],
                    "Set a strong credential. Empty passwords are unacceptable.")

        for cap in c.get("capabilities_added",[]):
            if cap in DANGEROUS_CAPS:
                self._f(cid,svc,"Dangerous Linux Capability Added: {}".format(cap),"critical",
                    "{}: {}".format(cap,DANGEROUS_CAPS[cap]),MITRE["caps"],
                    "Remove CAP_{}. Use only specific minimal capabilities.".format(cap))

        if not c.get("seccomp_profile"):
            self._f(cid,svc,"No Seccomp Profile Applied","medium",
                "Without seccomp container can make any Linux syscall.",MITRE["seccomp"],
                "Apply default Docker seccomp profile minimum.")

        if not c.get("apparmor_profile"):
            self._f(cid,svc,"No AppArmor Profile Applied","medium",
                "Without AppArmor no mandatory access controls on processes.",MITRE["seccomp"],
                "Apply docker-default AppArmor profile.")

        if not c.get("read_only_filesystem"):
            self._f(cid,svc,"Container Filesystem is Writable","medium",
                "Writable filesystem allows malware to write files and persist.",MITRE["root"],
                "Add --read-only flag. Mount tmpfs for /tmp at runtime.")

        vulns = c.get("image_vulnerabilities",0)
        age   = c.get("image_age_days",0)
        if vulns > 20:
            self._f(cid,svc,"Image Has {} Known Vulnerabilities".format(vulns),"critical",
                "Image '{}' has {} unpatched CVEs.".format(c["image"],vulns),MITRE["vuln"],
                "Rebuild with updated base. Implement image scanning in CI/CD (Trivy/Snyk).")
        elif vulns > 5:
            self._f(cid,svc,"Image Has {} Known Vulnerabilities".format(vulns),"high",
                "Image '{}' has {} unpatched CVEs.".format(c["image"],vulns),MITRE["vuln"],
                "Update base image. Patch critical CVEs within 72 hours.")

        if age > 365:
            self._f(cid,svc,"Image Not Updated in {} Days".format(age),"high",
                "Image '{}' is {} days old.".format(c["image"],age),MITRE["vuln"],
                "Establish monthly image update policy. Automate with Dependabot.")

        if c.get("image_tag") == "latest":
            self._f(cid,svc,"Image Using ':latest' Tag","medium",
                "Using ':latest' makes deployments non-deterministic.",MITRE["vuln"],
                "Pin to specific digest or semantic version tag in production.")

        if 22 in c.get("exposed_ports",[]):
            self._f(cid,svc,"SSH Port 22 Exposed in Container","high",
                "Containers should not expose SSH.",MITRE["ssh"],
                "Remove SSH. Use kubectl exec or docker exec for debugging.")
