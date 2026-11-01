"""
Correlate detections from the same source IP into incidents.

Logic (simple):
- Group detections by source_ip.
- If a source has any detections within CORRELATION_WINDOW of each other,
  merge them into one incident (or extend an existing open one).
- Severity is computed by detection/scoring.py.
"""
import datetime
import config
from database.db import (
    get_latest_incident_for_source,
    create_incident,
    update_incident,
)
from detection.scoring import incident_severity


def _ts(iso):
    """Parse an ISO-8601 UTC string like '2026-10-31T00:00:00Z'."""
    return datetime.datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=datetime.timezone.utc
    )


def correlate(detections):
    """
    Given a list of fresh detection dicts, group them into incidents.

    Returns the list of incident IDs that were created or updated.
    """
    if not detections:
        return []

    # Group by source_ip.
    by_ip = {}
    for d in detections:
        by_ip.setdefault(d["source_ip"], []).append(d)

    incident_ids = []
    now_str = (
        datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )

    for src, dlist in by_ip.items():
        # Collect all event ids and rule ids for this source.
        all_event_ids = []
        all_rule_ids = []
        earliest = now_str
        latest = now_str
        for d in dlist:
            all_event_ids.extend(d.get("event_ids", []))
            rule_id = d.get("rule_id")
            if rule_id and rule_id not in all_rule_ids:
                all_rule_ids.append(rule_id)
            det_at = d.get("detected_at", now_str)
            if det_at < earliest:
                earliest = det_at
            if det_at > latest:
                latest = det_at

        severity = incident_severity(dlist)

        # Check if there's a recent open incident for this source.
        existing = get_latest_incident_for_source(src)
        if existing:
            try:
                gap = (_ts(earliest) - _ts(existing["end_time"])).total_seconds()
            except Exception:
                gap = config.CORRELATION_WINDOW + 1

            if gap <= config.CORRELATION_WINDOW:
                # Extend the existing incident.
                merged_rule_ids = list(
                    set(existing.get("rule_ids", []) + all_rule_ids)
                )
                merged_event_ids = list(
                    set(existing.get("event_ids", []) + all_event_ids)
                )
                update_incident(
                    existing["id"],
                    latest,
                    severity,
                    merged_rule_ids,
                    merged_event_ids,
                )
                incident_ids.append(existing["id"])
                continue

        # Create a new incident.
        inc_id = create_incident(
            {
                "source_ip": src,
                "start_time": earliest,
                "end_time": latest,
                "severity": severity,
                "rule_ids": all_rule_ids,
                "event_ids": list(set(all_event_ids)),
            }
        )
        incident_ids.append(inc_id)

    return incident_ids
