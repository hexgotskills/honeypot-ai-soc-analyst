"""
analyst/validation.py – Validate structured AI SOC analyst reports.
"""
import json

REQUIRED_FIELDS = [
    "summary",
    "technical_analysis",
    "attack_stage",
    "attack_technique",
    "evidence",
    "confidence",
    "recommended_actions",
    "false_positive_notes",
    "limitations",
]

VALID_ATTACK_STAGES = {
    "reconnaissance",
    "credential access",
    "discovery",
    "multi-stage",
}

def validate_report(text, allowed_event_ids=None, allowed_rule_ids=None, expected_severity=None):
    """Validate AI report JSON.
    Returns (report_dict, None) on success, or (None, error_str) on failure.
    """
    if not text or not isinstance(text, str):
        return None, "empty or non-string input"

    # Strip markdown fences if present
    t = text.strip()
    if t.startswith("```"):
        lines = t.splitlines()
        t = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

    try:
        obj = json.loads(t)
    except Exception:
        return None, "not valid JSON"

    if not isinstance(obj, dict):
        return None, "not a JSON object"

    # 1. Check all required fields exist
    for field in REQUIRED_FIELDS:
        if field not in obj:
            return None, f"missing field: {field}"

    # 2. Check types of fields
    if not isinstance(obj["summary"], str) or not obj["summary"].strip():
        return None, "summary must be a non-empty string"

    if not isinstance(obj["technical_analysis"], str) or not obj["technical_analysis"].strip():
        return None, "technical_analysis must be a non-empty string"

    if not isinstance(obj["attack_stage"], str) or obj["attack_stage"].strip().lower() not in VALID_ATTACK_STAGES:
        return None, (
            f"attack_stage must be one of reconnaissance, credential access, discovery, multi-stage "
            f"(got '{obj.get('attack_stage')}')"
        )

    # attack_technique can be string (e.g. 'T1110 - Brute Force') or dict with id/name
    tech = obj["attack_technique"]
    if not (isinstance(tech, str) and tech.strip()) and not (isinstance(tech, dict) and "id" in tech and "name" in tech):
        return None, "attack_technique must be a MITRE ATT&CK technique string or dict"

    # 3. Check confidence
    conf = obj["confidence"]
    if not isinstance(conf, str) or not any(w in conf.lower() for w in ("low", "medium", "high")):
        return None, "confidence must indicate low, medium, or high with reasoning"

    # 4. Check recommended_actions (3 to 5 concrete steps)
    recs = obj["recommended_actions"]
    if not isinstance(recs, list) or not (3 <= len(recs) <= 5):
        return None, f"recommended_actions must be a list of 3 to 5 concrete steps (got {len(recs) if isinstance(recs, list) else 'non-list'})"

    # 5. Check false_positive_notes & limitations
    if not isinstance(obj["false_positive_notes"], (str, list)):
        return None, "false_positive_notes must be string or list"
    if not isinstance(obj["limitations"], (str, list)):
        return None, "limitations must be string or list"

    # 6. Check evidence
    evidence = obj["evidence"]
    if not isinstance(evidence, list):
        return None, "evidence must be a list"

    allowed_events = set(allowed_event_ids) if allowed_event_ids is not None else None
    allowed_rules = set(allowed_rule_ids) if allowed_rule_ids is not None else None

    for item in evidence:
        if not isinstance(item, dict):
            return None, "evidence items must be JSON objects"

        # Collect any cited event IDs
        cited_eids = []
        if "event_id" in item and item["event_id"] is not None:
            cited_eids.append(item["event_id"])
        if "event_ids" in item and isinstance(item["event_ids"], list):
            cited_eids.extend(item["event_ids"])

        # Collect any cited rule IDs
        cited_rids = []
        if "rule_id" in item and item["rule_id"] is not None:
            cited_rids.append(str(item["rule_id"]))
        if "rule_ids" in item and isinstance(item["rule_ids"], list):
            cited_rids.extend([str(r) for r in item["rule_ids"]])

        if not cited_eids and not cited_rids:
            return None, "evidence item must cite an event id or rule id"

        # Validate event IDs against allowed set
        if allowed_events is not None:
            for eid in cited_eids:
                if eid not in allowed_events:
                    return None, f"event id {eid} not in allowed ids"

        # Validate rule IDs against allowed set (if allowed rules specified)
        if allowed_rules is not None and len(allowed_rules) > 0:
            for rid in cited_rids:
                if rid not in allowed_rules:
                    return None, f"rule id {rid} not in allowed ids"

    # 7. Check severity if expected_severity is provided
    if expected_severity is not None and "severity" in obj and obj["severity"]:
        if str(obj["severity"]).strip().lower() != str(expected_severity).strip().lower():
            return None, f"states a severity different from stored one: '{obj['severity']}' vs '{expected_severity}'"

    return obj, None

