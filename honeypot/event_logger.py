# Simple event logger for the honeypot
# Stores events in the SQLite database.
import datetime
from datetime import timezone

import json
import config
from database.db import insert_event

def log_event(source_ip, service, event_type, outcome, metadata):
    """Validate and store an event, returning its id.
    Empty required fields cause a message and return None.
    """
    if not source_ip:
        print("source_ip is required")
        return None
    if not service:
        print("service is required")
        return None
    if not event_type:
        print("event_type is required")
        return None
    # Truncate overly long values.
    source_ip = source_ip[:100]
    service = service[:50]
    event_type = event_type[:50]
    outcome = (outcome or "")[:50]
    # Ensure metadata is a dict and not too big.
    if not isinstance(metadata, dict):
        metadata = {}
    meta_json = json.dumps(metadata)
    if len(meta_json) > 1000:
        metadata = {"note": "metadata too long"}
    # Build UTC timestamp.
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        event = {
            "timestamp": timestamp,
            "source_ip": source_ip,
            "service": service,
            "event_type": event_type,
            "outcome": outcome,
            "metadata": metadata,
        }
        return insert_event(event)
    except Exception as e:
        print(e)
        return None
