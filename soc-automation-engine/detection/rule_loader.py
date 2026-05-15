"""
Rule Loader — Loads YAML-based detection rules from disk.
"""
import yaml
import logging

logger = logging.getLogger(__name__)

REQUIRED_RULE_FIELDS = ["name", "threshold"]


def load_rules(path):
    try:
        with open(path, "r") as f:
            rules = yaml.safe_load(f)
    except FileNotFoundError:
        logger.error(f"Rules file not found: {path}")
        return []
    except yaml.YAMLError as e:
        logger.error(f"Failed to parse YAML rules: {e}")
        return []

    valid_rules = []
    for rule in rules:
        if all(field in rule for field in REQUIRED_RULE_FIELDS):
            valid_rules.append(rule)
        else:
            logger.warning(f"Skipping malformed rule: {rule.get('name', 'UNKNOWN')}")

    logger.info(f"Loaded {len(valid_rules)} valid rule(s).")
    return valid_rules
