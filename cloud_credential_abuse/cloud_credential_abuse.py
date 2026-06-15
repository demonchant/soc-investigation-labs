"""
Cloud Credential Abuse Detector — AWS/GCP/Azure IAM Anomaly Engine
===================================================================
Detects cloud credential theft and abuse: stolen IAM keys, role
assumption chains, resource enumeration, crypto-mining spin-up,
data exfiltration via S3/GCS/Blob, and privilege escalation in cloud.

Coverage: AWS CloudTrail, GCP Audit Logs, Azure Activity Logs (NDJSON).

MITRE ATT&CK:
  T1528     - Steal Application Access Token
  T1537     - Transfer Data to Cloud Account
  T1578     - Modify Cloud Compute Infrastructure
  T1580     - Cloud Infrastructure Discovery
  T1552.005 - Cloud Instance Metadata API

Author: Oladapo Damilola (Wizardskull)
"""

import json
import sys
from collections import defaultdict
from datetime import datetime, timezone


CONFIG = {
    "enum_api_threshold": 15,           # >15 List/Describe calls = enumeration
    "new_region_alert": True,           # flag activity in regions never used before
    "crypto_instance_types": {          # GPU/compute-optimized = mining
        "p2.xlarge", "p3.2xlarge", "p3.8xlarge", "g4dn.xlarge",
        "a100", "v100",  # GCP
        "Standard_NC", "Standard_ND",   # Azure
    },
    "sensitive_api_calls": {            # high-value API operations
        # AWS
        "GetSecretValue", "GetParameter", "GetParameters",
        "AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity",
        "CreateAccessKey", "UpdateAccessKey", "PutUserPolicy",
        "AttachUserPolicy", "AttachRolePolicy", "CreateLoginProfile",
        "PutBucketPolicy", "DeleteBucketPolicy",
        "GetObject", "ListBuckets", "ListObjects",
        # GCP
        "storage.objects.get", "storage.buckets.list",
        "iam.serviceAccountKeys.create", "iam.roles.update",
        # Azure
        "Microsoft.KeyVault/vaults/secrets/read",
        "Microsoft.Authorization/roleAssignments/write",
        "Microsoft.Storage/storageAccounts/listKeys/action",
    },
    "enumeration_patterns": {           # API calls indicating reconnaissance
        "List", "Describe", "Get", "Scan", "Search", "Query",
    },
    "data_exfil_services": {            # services used for cloud data theft
        "S3", "GCS", "AzureBlob", "BigQuery", "Athena",
    },
    "privilege_escalation_apis": {
        # AWS IAM privilege escalation paths (Rhino Security Labs research)
        "CreateAccessKey",              # create key for another user
        "UpdateAssumeRolePolicy",       # modify trust policy
        "AttachUserPolicy",             # attach admin policy
        "PutUserPolicy",                # inline admin policy
        "AttachGroupPolicy",
        "AddUserToGroup",               # add to admin group
        "UpdateLoginProfile",           # change console password
        "CreateLoginProfile",
        "PassRole",                     # pass privileged role to service
    },
}

KNOWN_CLOUD_PENTEST_UAS = [
    "aws-sdk-unknown", "ScoutSuite", "Prowler", "CloudMapper",
    "Pacu", "WeirdAAL", "enumerate-iam",
]


def parse_cloud_log(log_path: str) -> list:
    """
    Parse cloud audit logs (NDJSON).
    Normalized fields: timestamp, cloud, principal, api_call, region,
                       resource, src_ip, user_agent, error_code (optional)
    """
    events = []
    with open(log_path) as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                ev = json.loads(line)
                ts_raw = ev.get("timestamp", 0)
                ts = float(ts_raw) if isinstance(ts_raw, (int, float)) else \
                    datetime.fromisoformat(ts_raw.replace("Z", "+00:00")).timestamp()
                ev["ts"] = ts
                events.append(ev)
            except (json.JSONDecodeError, KeyError, ValueError) as e:
                print(f"[WARN] Line {line_num}: {e}", file=sys.stderr)
    return events


def detect_enumeration(events: list) -> list:
    """Detect cloud resource enumeration / reconnaissance."""
    alerts = []
    principal_calls = defaultdict(lambda: defaultdict(list))

    for ev in events:
        principal = ev.get("principal", "")
        api = ev.get("api_call", "")
        for enum_prefix in CONFIG["enumeration_patterns"]:
            if api.startswith(enum_prefix):
                principal_calls[principal][enum_prefix].append(ev)

    for principal, prefixes in principal_calls.items():
        total_enum = sum(len(v) for v in prefixes.values())
        if total_enum >= CONFIG["enum_api_threshold"]:
            ua = set(e.get("user_agent", "") for evts in prefixes.values() for e in evts)
            pentest_tool = any(
                any(tool.lower() in u.lower() for tool in KNOWN_CLOUD_PENTEST_UAS)
                for u in ua
            )
            alerts.append({
                "alert_type": "CLOUD_ENUMERATION",
                "severity": "CRITICAL" if pentest_tool else "HIGH",
                "mitre_technique": "T1580",
                "principal": principal,
                "enum_call_count": total_enum,
                "enum_prefixes_used": list(prefixes.keys()),
                "pentest_tool_detected": pentest_tool,
                "user_agents": list(ua)[:3],
            })
    return alerts


def detect_privilege_escalation(events: list) -> list:
    """Detect IAM privilege escalation chains."""
    alerts = []
    principal_privesc = defaultdict(list)

    for ev in events:
        api = ev.get("api_call", "")
        principal = ev.get("principal", "")
        if api in CONFIG["privilege_escalation_apis"]:
            principal_privesc[principal].append(ev)

    for principal, evts in principal_privesc.items():
        if len(evts) >= 2:  # Multiple privesc APIs = chained escalation
            apis_used = [e["api_call"] for e in evts]
            alerts.append({
                "alert_type": "CLOUD_PRIVILEGE_ESCALATION",
                "severity": "CRITICAL",
                "mitre_technique": "T1078.004",
                "principal": principal,
                "escalation_chain": apis_used,
                "event_count": len(evts),
                "resources": list({e.get("resource", "") for e in evts})[:5],
            })
    return alerts


def detect_credential_abuse(events: list) -> list:
    """Detect stolen/abused API keys via behavioral anomalies."""
    alerts = []
    principal_data = defaultdict(lambda: {
        "regions": set(), "ips": set(), "sensitive_calls": [],
        "assume_role_chains": [], "error_count": 0,
    })

    for ev in events:
        principal = ev.get("principal", "")
        region = ev.get("region", "")
        src_ip = ev.get("src_ip", "")
        api = ev.get("api_call", "")
        error = ev.get("error_code", "")

        d = principal_data[principal]
        if region:
            d["regions"].add(region)
        if src_ip:
            d["ips"].add(src_ip)

        if api in CONFIG["sensitive_api_calls"]:
            d["sensitive_calls"].append(ev)

        if "AssumeRole" in api:
            d["assume_role_chains"].append(ev)

        if error in ("AccessDenied", "UnauthorizedOperation", "AuthorizationError"):
            d["error_count"] += 1

    for principal, d in principal_data.items():
        issues = []
        score = 0

        # Multi-region activity from single key = credential sharing/theft
        if len(d["regions"]) >= 4:
            issues.append(f"activity in {len(d['regions'])} regions simultaneously")
            score += 25

        # Multi-IP source = credential distributed/leaked
        if len(d["ips"]) >= 3:
            issues.append(f"requests from {len(d['ips'])} different source IPs")
            score += 25

        # Sensitive API abuse
        if len(d["sensitive_calls"]) >= 5:
            apis = list({e["api_call"] for e in d["sensitive_calls"]})
            issues.append(f"sensitive API calls: {', '.join(apis[:3])}")
            score += 30

        # Role assumption chain (privilege escalation via role hopping)
        if len(d["assume_role_chains"]) >= 3:
            issues.append(f"role assumption chain: {len(d['assume_role_chains'])} hops")
            score += 20

        # High error rate = unauthorized probing
        if d["error_count"] >= 10:
            issues.append(f"access denied errors: {d['error_count']}")
            score += 15

        if score < 30:
            continue

        severity = "CRITICAL" if score >= 70 else "HIGH" if score >= 50 else "MEDIUM"
        alerts.append({
            "alert_type": "CLOUD_CREDENTIAL_ABUSE",
            "severity": severity,
            "mitre_technique": "T1528",
            "principal": principal,
            "abuse_score": min(score, 100),
            "indicators": issues,
            "regions_active": list(d["regions"]),
            "source_ips": list(d["ips"])[:5],
            "assume_role_count": len(d["assume_role_chains"]),
            "access_denied_count": d["error_count"],
        })

    return alerts


def detect_crypto_mining(events: list) -> list:
    """Detect cloud crypto-mining via instance type and API patterns."""
    alerts = []
    for ev in events:
        api = ev.get("api_call", "")
        resource = ev.get("resource", "")
        instance_type = ev.get("instance_type", "")
        principal = ev.get("principal", "")

        if any(api_kw in api for api_kw in ("RunInstances", "CreateInstance", "Deploy")):
            if instance_type in CONFIG["crypto_instance_types"]:
                alerts.append({
                    "alert_type": "CLOUD_CRYPTO_MINING",
                    "severity": "HIGH",
                    "mitre_technique": "T1578",
                    "principal": principal,
                    "instance_type": instance_type,
                    "api_call": api,
                    "resource": resource,
                    "description": f"GPU/compute instance launched by {principal} — potential crypto mining",
                })
    return alerts


def run_detection(events: list) -> list:
    all_alerts = []
    all_alerts.extend(detect_enumeration(events))
    all_alerts.extend(detect_privilege_escalation(events))
    all_alerts.extend(detect_credential_abuse(events))
    all_alerts.extend(detect_crypto_mining(events))

    now = datetime.now(timezone.utc).isoformat()
    for a in all_alerts:
        a["detection_timestamp"] = now
        a.setdefault("mitre_tactic", "Initial Access / Credential Access")
        a["recommended_action"] = (
            f"Revoke credentials for '{a.get('principal', 'unknown')}' immediately. "
            "Review all API activity in the last 30 days. "
            "Check for data exfiltration to external S3/GCS buckets. "
            "Audit IAM policies for unauthorized changes. "
            "Enable GuardDuty/Security Command Center if not already active."
        )

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    all_alerts.sort(key=lambda x: sev_order.get(x.get("severity", "MEDIUM"), 9))
    return all_alerts


def print_report(alerts: list):
    print("\n" + "═" * 70)
    print("  CLOUD CREDENTIAL ABUSE DETECTOR — THREAT REPORT")
    print("═" * 70)
    if not alerts:
        print("  ✅ No cloud credential abuse detected.")
        return
    print(f"  🚨 {len(alerts)} cloud threat(s)\n")
    for i, a in enumerate(alerts, 1):
        print(f"  [{i}] {a['severity']} — {a['alert_type']}")
        print(f"      Principal: {a.get('principal', 'N/A')}")
        if "indicators" in a:
            for ind in a["indicators"]:
                print(f"      ⚠ {ind}")
        if "description" in a:
            print(f"      {a['description']}")
        print(f"      MITRE: {a.get('mitre_technique', 'N/A')}")
        print()
    print("═" * 70)


def save_report(alerts, path):
    with open(path, "w") as f:
        json.dump({"total_alerts": len(alerts), "alerts": alerts}, f, indent=2)
    print(f"  📄 Report saved → {path}")


def main():
    log_path = sys.argv[1] if len(sys.argv) > 1 else "sample_cloud_audit.ndjson"
    out_path = sys.argv[2] if len(sys.argv) > 2 else "cloud_abuse_report.json"
    print(f"[*] Loading cloud audit log: {log_path}")
    events = parse_cloud_log(log_path)
    print(f"[*] Cloud events: {len(events)}")
    alerts = run_detection(events)
    print_report(alerts)
    save_report(alerts, out_path)


if __name__ == "__main__":
    main()
