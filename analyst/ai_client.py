"""
analyst/ai_client.py – AI client supporting both Gemini API and a structured mock provider.
"""
import json
import requests
import config
from analyst.enrich import get_mitre_technique_string

def generate_mock_report(package):
    """Generate a realistic structured AI SOC analyst report without an external API key.
    package: dict containing telemetry, events, rules, and optional incident fields.
    """
    events = package.get("events", [])
    rules = package.get("rules", [])

    # Extract source IPs
    if package.get("source_ips"):
        source_ips = package["source_ips"]
    elif package.get("source_ip"):
        source_ips = [package["source_ip"]]
    else:
        ip_set = []
        for e in events:
            sip = e.get("source_ip")
            if sip and sip not in ip_set:
                ip_set.append(sip)
        source_ips = ip_set if ip_set else ["127.0.0.1"]

    rule_ids = [r.get("rule_id") for r in rules if isinstance(r, dict) and r.get("rule_id")]
    event_types = set()
    if package.get("event_counts"):
        event_types.update(package["event_counts"].keys())
    if package.get("event_type_counts"):
        event_types.update(package["event_type_counts"].keys())
    for e in events:
        if e.get("event_type"):
            event_types.add(e["event_type"])

    # Determine attack stage
    if len(event_types) > 1 or "COMBO-001" in rule_ids:
        attack_stage = "multi-stage"
    elif any(t in event_types for t in ("login_attempt",)) or "AUTH-001" in rule_ids:
        attack_stage = "credential access"
    elif any(t in event_types for t in ("decoy_resource_access",)) or "WEB-002" in rule_ids:
        attack_stage = "discovery"
    else:
        attack_stage = "reconnaissance"

    # Determine attack technique
    if attack_stage == "credential access":
        technique = get_mitre_technique_string("AUTH-001")
    elif attack_stage == "discovery":
        technique = get_mitre_technique_string("WEB-002")
    elif attack_stage == "multi-stage":
        technique = get_mitre_technique_string("COMBO-001")
    else:
        technique = get_mitre_technique_string("WEB-001")

    # Summary: strictly 2 sentences
    if len(source_ips) > 1:
        ip_list_str = ", ".join(source_ips[:3])
        summary = (
            f"Automated analysis identified honeypot interactions distributed across multiple distinct source IP addresses ({ip_list_str}). "
            f"The observed traffic pattern suggests coordinated or concurrent probing of lab services across multiple stages."
        )
    else:
        ip = source_ips[0]
        summary = (
            f"Automated analysis identified suspicious traffic originating from source IP {ip} targeting honeypot decoy services. "
            f"The observed activity shows repeated deliberate access patterns matching configured detection rules."
        )

    # Technical analysis: a paragraph explaining what each rule hit means and how the events connect.
    # If multiple source IPs, treat them separately.
    if len(source_ips) > 1:
        ip_parts = []
        for sip in source_ips:
            sip_evs = [e for e in events if e.get("source_ip") == sip]
            t_list = list({e.get("event_type") for e in sip_evs if e.get("event_type")}) or ["general probing"]
            ip_parts.append(f"source {sip} initiated {', '.join(t_list)}")
        ip_text = "; ".join(ip_parts)
        rules_desc = ", ".join([f"{r.get('rule_id')} ({r.get('reason', 'rule triggered')})" for r in rules]) if rules else "threshold anomalies"
        technical_analysis = (
            f"The captured telemetry encompasses events from multiple independent source addresses: {ip_text}. "
            f"Evaluation of detection rules ({rules_desc}) indicates that the sources engaged in sequential exploration of decoy resources. "
            f"Events connect chronologically from initial connection attempts to structured decoy resource requests, demonstrating organized testing of perimeter decoys rather than random background noise."
        )
    else:
        ip = source_ips[0]
        rules_desc = ", ".join([f"{r.get('rule_id')} ({r.get('reason', 'matched signature')})" for r in rules]) if rules else "frequency detection"
        technical_analysis = (
            f"The observed events show sequential interactions originating exclusively from source IP {ip}. "
            f"Detection rule hits ({rules_desc}) indicate that the client repeatedly exceeded rate or pattern thresholds on monitored services. "
            f"The connection sequence indicates initial service discovery immediately followed by structured probes, linking the initial contact directly with subsequent decoy engagement in a single continuous campaign."
        )

    # Evidence: items each with an event id or rule id and a short note
    evidence = []
    for r in rules[:2]:
        rid = r.get("rule_id")
        if rid:
            evidence.append({
                "rule_id": rid,
                "note": f"Rule {rid} triggered: {r.get('reason', 'condition matched')}",
            })
    for e in events[:3]:
        eid = e.get("id")
        if eid is not None:
            evidence.append({
                "event_id": eid,
                "note": f"Event {eid} ({e.get('event_type')}) recorded outcome '{e.get('outcome')}'",
            })
    if not evidence and events:
        evidence.append({
            "event_id": events[0]["id"],
            "note": "Initial honeypot event recorded",
        })

    # Recommended actions: 3 to 5 concrete steps
    recommended_actions = [
        "Block the offending source IP address at the perimeter firewall.",
        "Review authentication and application access logs for any collateral traffic.",
        "Inspect honeypot service configurations to verify no genuine credentials or sensitive data are exposed.",
        "Verify rate-limiting and intrusion prevention rules to automatically drop repeated probe bursts.",
    ]

    report = {
        "summary": summary,
        "technical_analysis": technical_analysis,
        "attack_stage": attack_stage,
        "attack_technique": technique,
        "evidence": evidence,
        "confidence": "medium - Consistent telemetry observed across multiple honeypot events matching deterministic detection rules.",
        "recommended_actions": recommended_actions,
        "false_positive_notes": "Decoy resources and honeypot ports have no legitimate business function; false positive likelihood is negligible in this isolated environment.",
        "limitations": "Analysis is based strictly on isolated honeypot telemetry within the private lab environment without external threat intelligence feeds.",
    }

    # If package has severity, include it to match stored severity
    if package.get("severity"):
        report["severity"] = package["severity"]

    # Multi-event additional fields if present in package
    if package.get("common_source_ips") or len(source_ips) > 0:
        report["common_source_ips"] = source_ips
    if package.get("time_span"):
        report["time_span"] = package["time_span"]
    if package.get("event_type_counts") or package.get("event_counts"):
        report["event_type_counts"] = package.get("event_type_counts") or package.get("event_counts")
    if package.get("sequence_of_actions"):
        report["sequence_of_actions"] = package["sequence_of_actions"]
    if package.get("likely_objective"):
        report["likely_objective"] = package["likely_objective"]
    if rule_ids:
        report["related_rules"] = rule_ids
    report["attack_techniques"] = [technique]

    return report


def ask_ai(prompt, package):
    """Query the configured AI provider. Returns raw JSON string."""
    if config.AI_PROVIDER == "mock":
        return json.dumps(generate_mock_report(package))

    if config.AI_PROVIDER == "gemini":
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{config.AI_MODEL}:generateContent"
        resp = requests.post(
            url,
            headers={"x-goog-api-key": config.AI_API_KEY},
            json={
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"responseMimeType": "application/json"},
            },
            timeout=30,
        )
        if resp.status_code != 200:
            raise Exception(f"Gemini {resp.status_code}: {resp.text[:200]}")
        return resp.json()["candidates"][0]["content"]["parts"][0]["text"]

    raise Exception(f"unknown provider: {config.AI_PROVIDER}")

