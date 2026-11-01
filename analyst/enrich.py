"""
analyst/enrich.py – Enrich honeypot events with category, technique, and MITRE ATT&CK mappings.
"""

MITRE_ATTACK_MAP = {
    # Event types
    "login_attempt": {"id": "T1110", "name": "Brute Force"},
    "http_request": {"id": "T1595", "name": "Active Scanning"},
    "decoy_resource_access": {"id": "T1083", "name": "File and Directory Discovery"},
    "blocked_attempt": {"id": "T1110", "name": "Brute Force"},
    # Detection Rules
    "AUTH-001": {"id": "T1110", "name": "Brute Force"},
    "WEB-001": {"id": "T1595", "name": "Active Scanning"},
    "WEB-002": {"id": "T1083", "name": "File and Directory Discovery"},
    "COMBO-001": {"id": "T1110", "name": "Brute Force / Multi-Stage"},
}

def enrich(event):
    """Return (category, technique, outcome) for an event dict."""
    category = event.get("service", "unknown")
    technique = event.get("event_type", "unknown")
    outcome = event.get("outcome", "unknown")
    return category, technique, outcome

def get_mitre_attack(key):
    """Return a dict with MITRE ATT&CK 'id' and 'name' for an event_type or rule_id."""
    return MITRE_ATTACK_MAP.get(key, {"id": "T1595", "name": "Active Scanning"})

def get_mitre_technique_string(key):
    """Return formatted MITRE ATT&CK string, e.g. 'T1110 - Brute Force'."""
    info = get_mitre_attack(key)
    return f"{info['id']} - {info['name']}"

