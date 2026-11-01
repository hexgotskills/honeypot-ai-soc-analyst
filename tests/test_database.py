import os
import json
import pytest
import config
from database.db import (
    initialize_database,
    insert_event,
    get_recent_events,
    get_events_by_source,
    get_events_after,
    create_incident,
    get_incident,
)
from honeypot.event_logger import log_event

@pytest.fixture(autouse=True)
def setup_db(tmp_path, monkeypatch):
    # Point the DB path to a temporary file.
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(config, "DATABASE_PATH", str(db_path))
    # Ensure the data directory exists (it will be created by get_connection).
    initialize_database()
    yield
    # No cleanup needed; tmp_path will be removed.

def test_insert_and_get_recent():
    event = {
        "timestamp": "2026-10-31T00:00:00Z",
        "source_ip": "1.2.3.4",
        "service": "tcp_login_decoy",
        "event_type": "login_attempt",
        "outcome": "failed",
        "metadata": {"foo": "bar"},
    }
    ev_id = insert_event(event)
    recent = get_recent_events(1)
    assert recent
    fetched = recent[0]
    assert fetched["id"] == ev_id
    assert fetched["source_ip"] == event["source_ip"]
    assert fetched["metadata"] == event["metadata"]

def test_persistence():
    event = {
        "timestamp": "2026-10-31T00:00:01Z",
        "source_ip": "5.6.7.8",
        "service": "tcp_login_decoy",
        "event_type": "login_attempt",
        "outcome": "failed",
        "metadata": {},
    }
    insert_event(event)
    # Open a new connection via the helper.
    recent = get_recent_events(10)
    assert any(e["source_ip"] == "5.6.7.8" for e in recent)

def test_events_filters():
    # Insert three events with different ids.
    insert_event({"timestamp": "2026-10-31T00:00:02Z", "source_ip": "9.9.9.9", "service": "svc", "event_type": "type", "outcome": None, "metadata": {}})
    insert_event({"timestamp": "2026-10-31T00:00:03Z", "source_ip": "9.9.9.9", "service": "svc", "event_type": "type", "outcome": None, "metadata": {}})
    evs = get_events_by_source("9.9.9.9")
    assert len(evs) == 2
    # Get events after the first inserted id.
    first_id = evs[0]["id"]
    later = get_events_after(first_id)
    assert len(later) == 1
    assert later[0]["id"] > first_id

def test_sql_injection_prevention():
    malicious_ip = "x'; DROP TABLE events;--"
    ev_id = insert_event({"timestamp": "2026-10-31T00:00:04Z", "source_ip": malicious_ip, "service": "svc", "event_type": "type", "outcome": None, "metadata": {}})
    # Should be stored as plain text.
    ev = get_recent_events(1)[0]
    assert ev["source_ip"] == malicious_ip
    # Table still works.
    more = get_events_by_source(malicious_ip)
    assert more[0]["id"] == ev_id

def test_incident_creation_and_fetch():
    # Insert two events to link.
    id1 = insert_event({"timestamp": "2026-10-31T00:00:05Z", "source_ip": "1.1.1.1", "service": "svc", "event_type": "type", "outcome": None, "metadata": {}})
    id2 = insert_event({"timestamp": "2026-10-31T00:00:06Z", "source_ip": "1.1.1.1", "service": "svc", "event_type": "type", "outcome": None, "metadata": {}})
    incident = {
        "source_ip": "1.1.1.1",
        "start_time": "2026-10-31T00:00:00Z",
        "end_time": "2026-10-31T01:00:00Z",
        "severity": "low",
        "rule_ids": ["r1", "r2"],
        "event_ids": [id1, id2],
    }
    inc_id = create_incident(incident)
    fetched = get_incident(inc_id)
    assert fetched["source_ip"] == incident["source_ip"]
    assert set(fetched["event_ids"]) == set(incident["event_ids"])
    assert fetched["rule_ids"] == incident["rule_ids"]

def test_log_event_validation():
    # Empty source_ip returns None.
    assert log_event("", "svc", "type", None, {}) is None
    # Very long service name is cut to 50 chars.
    long_name = "a" * 100
    ev_id = log_event("2.2.2.2", long_name, "type", None, {})
    ev = get_recent_events(1)[0]
    assert ev["service"] == long_name[:50]
