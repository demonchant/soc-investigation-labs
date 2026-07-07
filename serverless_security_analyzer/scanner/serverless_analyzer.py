"""
Serverless & Lambda Security Analyzer
Audits serverless function configurations for overprivileged IAM roles,
exposed event sources, hardcoded secrets, disabled logging,
deprecated runtimes, and cross-function blast radius.
"""
import re, logging
from collections import defaultdict
logger = logging.getLogger(__name__)

MITRE = {
    "privesc":  "T1078.004 - Valid Accounts: Cloud Accounts (over-privileged role)",
    "secret":   "T1552.005 - Unsecured Credentials: Cloud Instance Metadata",
    "inject":   "T1190 - Exploit Public-Facing Application (event source injection)",
    "persist":  "T1525 - Implant Internal Image (malicious layer)",
    "exfil":    "T1537 - Transfer Data to Cloud Account",
    "evasion":  "T1562.008 - Disable or Modify Cloud Logs",
    "recon":    "T1580 - Cloud Infrastructure Discovery",
}

DANGEROUS_ACTIONS = {
    "*":                             ("full AWS access", 40),
    "iam:*":                         ("full IAM control", 40),
    "iam:PassRole":                  ("PassRole escalation", 25),
    "iam:CreateAccessKey":           ("credential creation", 20),
    "iam:AttachUserPolicy":          ("policy attachment escalation", 20),
    "iam:AttachRolePolicy":          ("role policy attachment", 20),
    "s3:*":                          ("full S3 access", 15),
    "ec2:*":                         ("full EC2 control", 15),
    "lambda:*":                      ("Lambda self-modification", 15),
    "secretsmanager:GetSecretValue": ("secret read access", 10),
    "kms:Decrypt":                   ("decrypt all KMS data", 10),
    "dynamodb:*":                    ("full DynamoDB access", 10),
}

RISKY_SOURCES = {
    "apigateway": ("HTTP endpoint", "critical",
                   "public HTTP trigger — validate all input, auth every route"),
    "cognito":    ("Cognito user pool trigger", "high",
                   "auth flow trigger — injection here breaks authentication"),
    "sns":        ("SNS topic", "medium",
                   "message content not authenticated by default"),
    "s3":         ("S3 bucket events", "medium",
                   "validate object key and content before processing"),
    "sqs":        ("SQS queue", "low",
                   "validate message schema strictly"),
}

SECRET_PATTERN = re.compile(
    r"(password|passwd|secret|api_key|apikey|token|credential|"
    r"aws_secret|private_key|client_secret|auth_token)", re.I)

DEPRECATED_RUNTIMES = {
    "python2.7", "python3.6", "python3.7",
    "nodejs8.10", "nodejs10.x", "nodejs12.x",
    "dotnetcore2.1", "dotnetcore3.1",
    "ruby2.5", "java8",
}

class ServerlessAnalyzer:
    def __init__(self): self.findings = []

    def analyze_all(self, data):
        fns = data.get("functions", [])
        for fn in fns:
            self._analyze_fn(fn)
        self._cross_fn_analysis(fns)
        return self.findings

    def _f(self, fn, title, sev, detail, mitre, rec):
        self.findings.append({"function": fn, "title": title, "severity": sev,
            "detail": detail, "mitre_technique": mitre, "recommendation": rec})

    def _analyze_fn(self, fn):
        name    = fn.get("function_name", "?")
        runtime = fn.get("runtime", "")
        role    = fn.get("iam_role", {})
        env     = fn.get("environment_variables", {})
        sources = fn.get("event_sources", [])
        cfg     = fn.get("config", {})
        layers  = fn.get("layers", [])
        vpc     = fn.get("vpc_config", {})

        self._check_iam(name, role)
        self._check_env_secrets(name, env)
        self._check_event_sources(name, sources)

        # Logging disabled
        if not cfg.get("cloudwatch_logs_enabled", True):
            self._f(name, "CloudWatch Logging Disabled", "critical",
                "Function '{}' has logging disabled — all invocations are invisible "
                "to SIEM, audit trail, and IR investigators.".format(name),
                MITRE["evasion"],
                "Enable CloudWatch Logs immediately. Review who disabled logging and when.")

        # Tracing disabled
        if not cfg.get("tracing_enabled"):
            self._f(name, "Active Tracing (X-Ray) Disabled", "low",
                "Function '{}' has no distributed tracing — anomalous downstream "
                "service calls are harder to detect.".format(name),
                MITRE["recon"],
                "Enable X-Ray active tracing. Anomalous call patterns signal compromise.")

        # Zero reserved concurrency silences function
        if cfg.get("reserved_concurrency") == 0:
            self._f(name, "Reserved Concurrency = 0 — Function Cannot Execute", "high",
                "Function '{}' has reserved_concurrency=0 and will never run. "
                "If this is a security function (log processor, alerter), "
                "it is silently failing.".format(name),
                MITRE["evasion"],
                "Verify intentional. A security function at zero concurrency "
                "provides no protection.")

        # Excessive timeout
        timeout = cfg.get("timeout_seconds", 0)
        if timeout > 600:
            self._f(name, "Excessive Timeout: {}s".format(timeout), "medium",
                "Function '{}' has a {}-second timeout — long-running functions "
                "are susceptible to slow-drip exfiltration and expensive abuse.".format(
                    name, timeout),
                MITRE["exfil"],
                "Reduce timeout to minimum required. Use Step Functions "
                "for long workflows instead of single long-running Lambda.")

        # Deprecated runtime
        if runtime.lower() in DEPRECATED_RUNTIMES:
            self._f(name, "Deprecated Runtime: {}".format(runtime), "high",
                "Function '{}' uses end-of-life runtime '{}' — "
                "no security patches, unaddressed CVEs.".format(name, runtime),
                MITRE["persist"],
                "Migrate to a supported runtime. EOL runtimes contain "
                "unfixed vulnerabilities actively targeted by attackers.")

        # No version control
        if not fn.get("published_versions") and not fn.get("aliases"):
            self._f(name, "No Version Control or Aliases", "low",
                "Function '{}' has no published versions or aliases — "
                "code changes are immediate with no rollback capability.".format(name),
                MITRE["persist"],
                "Publish versions and use aliases (live/dev). "
                "Enables instant rollback if malicious code is deployed.")

        # Unverified layers
        for layer in layers:
            if not layer.get("verified_owner"):
                self._f(name, "Unverified Layer: {}".format(layer.get("name","?")), "high",
                    "Function '{}' uses layer '{}' from unverified owner. "
                    "Malicious layers can intercept all function execution.".format(
                        name, layer.get("name","?")),
                    MITRE["persist"],
                    "Audit layer content. Only use layers from internal "
                    "verified sources or official AWS-published layers.")

        # API-triggered without VPC
        if not vpc.get("vpc_id") and any(
            s.get("type","").lower() == "apigateway" for s in sources
        ):
            self._f(name, "Public API Function Without VPC Isolation", "medium",
                "Function '{}' is publicly triggered (API Gateway) and runs "
                "outside any VPC — has direct internet egress.".format(name),
                MITRE["exfil"],
                "Place function inside VPC with NAT gateway for controlled egress. "
                "Use VPC endpoints for AWS service calls.")

    def _check_iam(self, name, role):
        actions   = role.get("actions", [])
        resources = role.get("resources", [])
        role_name = role.get("role_name", "?")
        score     = 0
        hits      = []

        for action in actions:
            if action in DANGEROUS_ACTIONS:
                desc, weight = DANGEROUS_ACTIONS[action]
                score  += weight
                hits.append("{} ({})".format(action, desc))

        wildcard = "*" in resources

        if score >= 40 or (score >= 15 and wildcard):
            sev = "critical" if score >= 40 else "high"
            self._f(name,
                "Over-Privileged Lambda Role: {} (score {})".format(role_name, score),
                sev,
                "Function '{}' role '{}' grants: {}. Resource scope: {}.".format(
                    name, role_name, "; ".join(hits[:3]),
                    "ALL resources (*)" if wildcard else "scoped"),
                MITRE["privesc"],
                "Apply least-privilege. Grant only the specific actions this function "
                "actually calls, scoped to specific resource ARNs. "
                "Use IAM Access Analyzer to generate policy from actual usage.")
        elif score >= 10:
            self._f(name, "Elevated Role Permissions: {}".format(role_name), "medium",
                "Function '{}' role has elevated permissions: {}.".format(
                    name, "; ".join(hits)),
                MITRE["privesc"],
                "Review whether all permissions are actively used. "
                "Run IAM Access Analyzer to identify and remove unused permissions.")

    def _check_env_secrets(self, name, env):
        for var_name, var_value in env.items():
            if SECRET_PATTERN.search(var_name):
                if (var_value and
                    not var_value.startswith("{{") and
                    "arn:aws:secretsmanager" not in var_value and
                    "arn:aws:ssm" not in var_value):
                    self._f(name,
                        "Hardcoded Secret in Env Var: {}".format(var_name), "critical",
                        "Function '{}' stores '{}' as plaintext env var — "
                        "visible in Lambda console, CloudTrail, and process listings.".format(
                            name, var_name),
                        MITRE["secret"],
                        "Move to AWS Secrets Manager or SSM Parameter Store (SecureString). "
                        "Rotate the exposed value immediately.")

    def _check_event_sources(self, name, sources):
        for source in sources:
            stype = source.get("type","").lower()
            if stype not in RISKY_SOURCES:
                continue
            label, sev, advice = RISKY_SOURCES[stype]
            authenticated = source.get("authenticated", True)
            # Unauthenticated public trigger is worse
            if not authenticated and sev == "critical":
                sev = "critical"
                advice += " WARNING: no authentication on this trigger."
            if sev in ("critical","high"):
                self._f(name,
                    "Risky Event Source: {} ({})".format(stype.upper(), label), sev,
                    "Function '{}' triggered by {} — {}.".format(name, label, advice),
                    MITRE["inject"],
                    "Validate and sanitize all event payload fields before processing. "
                    + ("Enable API Gateway authentication (Cognito/Lambda Authorizer). "
                       if stype == "apigateway" else "Implement strict input schema validation."))

    def _cross_fn_analysis(self, fns):
        role_map = defaultdict(list)
        for fn in fns:
            role_name = fn.get("iam_role", {}).get("role_name","")
            if role_name:
                role_map[role_name].append(fn.get("function_name","?"))
        for role, fn_list in role_map.items():
            if len(fn_list) > 1:
                self._f("CROSS-FUNCTION",
                    "Shared IAM Role Across {} Functions: {}".format(len(fn_list), role),
                    "medium",
                    "Role '{}' shared by: {}. Compromise of any one function "
                    "grants its permissions to effectively all sharing functions.".format(
                        role, ", ".join(fn_list)),
                    MITRE["privesc"],
                    "Create per-function roles with only the permissions each function needs. "
                    "Shared roles violate least-privilege and expand blast radius.")
