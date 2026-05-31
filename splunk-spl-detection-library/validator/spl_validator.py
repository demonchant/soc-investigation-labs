"""
SPL Rule Validator — Validates detection rules for required fields,
SPL syntax completeness, and MITRE technique format.
Simulates a CI/CD gate for a detection-as-code pipeline.
"""
import re, logging
logger = logging.getLogger(__name__)

REQUIRED_FIELDS = ["id", "name", "mitre", "severity", "spl", "description", "response"]
VALID_SEVERITIES = {"critical", "high", "medium", "low", "informational"}
MITRE_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")
SPL_REQUIRED_KEYWORDS = ["index=", "|"]
ID_PATTERN = re.compile(r"^SPL-\d{3,}$")


class SPLValidator:
    def validate_all(self, rules):
        results = []
        passed = failed = 0
        for rule in rules:
            result = self._validate_rule(rule)
            results.append(result)
            if result["status"] == "PASS":
                passed += 1
            else:
                failed += 1
        summary = {
            "total": len(rules), "passed": passed, "failed": failed,
            "pass_rate": round(passed / len(rules) * 100, 1) if rules else 0,
            "results": results
        }
        logger.info(f"Validation complete: {passed}/{len(rules)} rules passed.")
        return summary

    def _validate_rule(self, rule):
        errors = []
        warnings = []

        # Required fields
        for f in REQUIRED_FIELDS:
            if f not in rule or not rule[f]:
                errors.append(f"Missing required field: '{f}'")

        # ID format
        rid = rule.get("id", "")
        if not ID_PATTERN.match(rid):
            errors.append(f"Invalid ID format '{rid}' — expected SPL-NNN")

        # Severity
        sev = rule.get("severity", "").lower()
        if sev and sev not in VALID_SEVERITIES:
            errors.append(f"Invalid severity '{sev}'")

        # MITRE format (strip description after space)
        mitre_raw = rule.get("mitre", "")
        mitre_id = mitre_raw.split(" ")[0] if mitre_raw else ""
        if mitre_id and not MITRE_PATTERN.match(mitre_id):
            errors.append(f"Invalid MITRE ID format: '{mitre_id}'")

        # SPL basic completeness
        spl = rule.get("spl", "")
        for kw in SPL_REQUIRED_KEYWORDS:
            if kw not in spl:
                errors.append(f"SPL missing required keyword: '{kw}'")

        # SPL warnings
        if "stats" not in spl and "search" not in spl:
            warnings.append("SPL has no aggregation — may produce high event volume")
        if "| table" not in spl:
            warnings.append("SPL missing | table — output fields not explicitly defined")
        if "tuning_notes" not in rule:
            warnings.append("No tuning_notes provided — FP guidance missing")

        return {
            "id": rid,
            "name": rule.get("name", ""),
            "status": "FAIL" if errors else "PASS",
            "errors": errors,
            "warnings": warnings
        }
