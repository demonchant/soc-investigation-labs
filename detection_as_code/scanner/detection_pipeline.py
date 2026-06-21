import re, logging
from collections import defaultdict
logger = logging.getLogger(__name__)

MITRE = {
    "lint":     "Detection Engineering - Rule Syntax Validation",
    "test":     "Detection Engineering - CI Test Coverage",
    "perf":     "Detection Engineering - Rule Performance Risk",
    "deploy":   "Detection Engineering - Deployment Gate",
}

REQUIRED_FIELDS = {"rule_id", "title", "detection", "condition", "mitre_technique", "level"}
VALID_LEVELS = {"critical", "high", "medium", "low", "informational"}

class DetectionPipeline:
    """
    Simulates a CI/CD pipeline for detection rules:
      LINT  -> structural validation
      TEST  -> run against labeled event corpus, compute precision/recall
      GATE  -> pass/fail deployment decision based on thresholds
    """
    def __init__(self, min_precision=0.85, min_recall=0.80):
        self.findings = []
        self.min_precision = min_precision
        self.min_recall = min_recall

    def run_pipeline(self, data):
        rules = data.get("rules", [])
        corpus = data.get("test_corpus", [])
        for rule in rules:
            lint_result = self._lint(rule)
            test_result = self._test(rule, corpus) if lint_result["passed"] else None
            self._gate(rule, lint_result, test_result)
        return self.findings

    def _f(self, rule_id, stage, title, sev, detail, mitre, rec):
        self.findings.append({"rule_id": rule_id, "stage": stage, "title": title,
            "severity": sev, "detail": detail, "mitre_technique": mitre, "recommendation": rec})

    # ---------- STAGE 1: LINT ----------
    def _lint(self, rule):
        rid = rule.get("rule_id", "UNKNOWN")
        errors = []

        missing = REQUIRED_FIELDS - set(rule.keys())
        if missing:
            errors.append("missing required fields: {}".format(", ".join(sorted(missing))))

        level = rule.get("level", "").lower()
        if level and level not in VALID_LEVELS:
            errors.append("invalid level '{}' (must be one of {})".format(level, VALID_LEVELS))

        detection = rule.get("detection", {})
        if not detection:
            errors.append("empty detection block — rule cannot ever fire")
        else:
            for sel_name, fields in detection.items():
                if sel_name == "condition":
                    continue
                if not isinstance(fields, dict) or not fields:
                    errors.append("selection '{}' has no field conditions".format(sel_name))
                # flag single broad field with no modifier (high FP risk)
                bare_fields = [k for k in fields if "|" not in k]
                if bare_fields and len(fields) == 1:
                    errors.append("selection '{}' uses bare equality on '{}' — consider contains/endswith".format(
                        sel_name, bare_fields[0]))

        mitre = rule.get("mitre_technique", "")
        if mitre and not re.match(r"^T\d{4}(\.\d{3})?$", mitre):
            errors.append("malformed MITRE technique ID: '{}'".format(mitre))

        if errors:
            for e in errors:
                self._f(rid, "LINT", "Lint Error: {}".format(rid), "high",
                    e, MITRE["lint"], "Fix rule syntax before this rule can enter the test stage.")
            return {"passed": False, "errors": errors}

        return {"passed": True, "errors": []}

    # ---------- STAGE 2: TEST ----------
    def _evaluate(self, detection, condition, event):
        results = {}
        for sel_name, fields in detection.items():
            match = True
            for field_expr, value in fields.items():
                parts = field_expr.split("|")
                field = parts[0]
                mods = parts[1:]
                ev_val = str(event.get(field, "")).lower()
                if "endswith" in mods:
                    ok = ev_val.endswith(str(value).lower())
                elif "contains" in mods and "any" in mods:
                    vals = value if isinstance(value, list) else [value]
                    ok = any(str(v).lower() in ev_val for v in vals)
                elif "contains" in mods and "all" in mods:
                    vals = value if isinstance(value, list) else [value]
                    ok = all(str(v).lower() in ev_val for v in vals)
                elif "contains" in mods:
                    ok = str(value).lower() in ev_val
                else:
                    ok = ev_val == str(value).lower()
                if not ok:
                    match = False
                    break
            results[sel_name] = match
        cond = condition.lower()
        for name, res in results.items():
            cond = cond.replace(name.lower(), str(res))
        try:
            return eval(cond)
        except Exception:
            return any(results.values())

    def _test(self, rule, corpus):
        rid = rule["rule_id"]
        tp = fp = fn = tn = 0
        fp_cases, fn_cases = [], []

        for case in corpus:
            expected = case.get("expected_rule") == rid
            fired = self._evaluate(rule["detection"], rule["condition"], case["event"])
            if fired and expected:   tp += 1
            elif fired and not expected:
                fp += 1; fp_cases.append(case["case_id"])
            elif not fired and expected:
                fn += 1; fn_cases.append(case["case_id"])
            else: tn += 1

        precision = tp / (tp+fp) if (tp+fp) else 1.0
        recall    = tp / (tp+fn) if (tp+fn) else (1.0 if tp==0 and fn==0 else 0.0)

        if fp_cases:
            self._f(rid, "TEST", "False Positives in Test Corpus: {}".format(rid), "high",
                "Rule fired incorrectly on: {}.".format(", ".join(fp_cases)),
                MITRE["test"], "Tighten selection logic — add distinguishing conditions.")
        if fn_cases:
            self._f(rid, "TEST", "False Negatives in Test Corpus: {}".format(rid), "critical",
                "Rule MISSED known-malicious cases: {}.".format(", ".join(fn_cases)),
                MITRE["test"], "Broaden detection patterns — rule has a coverage gap against known TTPs.")

        return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
                "precision": round(precision,3), "recall": round(recall,3)}

    # ---------- STAGE 3: GATE ----------
    def _gate(self, rule, lint_result, test_result):
        rid = rule.get("rule_id","UNKNOWN")
        if not lint_result["passed"]:
            self._f(rid, "GATE", "Deployment BLOCKED: {}".format(rid), "critical",
                "Rule failed lint stage — cannot proceed to deployment.",
                MITRE["deploy"], "Resolve lint errors before resubmitting to pipeline.")
            return

        precision, recall = test_result["precision"], test_result["recall"]
        if precision < self.min_precision or recall < self.min_recall:
            self._f(rid, "GATE", "Deployment BLOCKED: {} (P={:.0%} R={:.0%})".format(
                rid, precision, recall), "high",
                "Rule does not meet minimum thresholds (precision>={:.0%}, recall>={:.0%}).".format(
                    self.min_precision, self.min_recall),
                MITRE["deploy"],
                "Improve rule quality before production deployment. Currently routed to "
                "'monitoring-only' tier, not active blocking.")
        else:
            self._f(rid, "GATE", "Deployment APPROVED: {} (P={:.0%} R={:.0%})".format(
                rid, precision, recall), "low",
                "Rule meets quality thresholds. Cleared for production deployment.",
                MITRE["deploy"], "Deploy to production SIEM. Schedule quarterly re-validation.")
