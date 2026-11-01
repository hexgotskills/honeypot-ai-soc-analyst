import socket
import threading
import pytest
import config
from database.db import (
    initialize_database,
    insert_event,
    count_table,
    clear_history,
    block_ip,
    unblock_ip,
    is_blocked,
    list_blocklist,
    get_setting,
    set_setting,
    create_incident,
)
from honeypot.tcp_decoy import handle_client
from honeypot.http_decoy import app as http_decoy_app
from detection.rules import run_all
import worker


@pytest.fixture(autouse=True)
def setup_db(tmp_path, monkeypatch):
    # Point DB to temporary path for isolated testing
    db_path = tmp_path / "test_countermeasures.db"
    monkeypatch.setattr(config, "DATABASE_PATH", str(db_path))
    initialize_database()
    # Reset worker watermark
    monkeypatch.setattr(worker, "_last_event_id", 0)
    yield


def test_block_unblock_round_trip():
    ip = "192.168.1.50"
    assert is_blocked(ip) is False

    # Block IP
    row_id = block_ip(ip, "Repeated brute force", block_type="manual")
    assert row_id is not None
    assert is_blocked(ip) is True

    # Listed in active blocks
    active_blocks = list_blocklist(active_only=True)
    assert any(b["ip"] == ip and b["block_type"] == "manual" for b in active_blocks)

    # Unblock IP
    count = unblock_ip(ip)
    assert count == 1
    assert is_blocked(ip) is False
    assert not any(b["ip"] == ip for b in list_blocklist(active_only=True))

    # All blocks history preserves record marked inactive
    all_blocks = list_blocklist(active_only=False)
    unblocked_entry = next(b for b in all_blocks if b["ip"] == ip)
    assert unblocked_entry["active"] == 0
    assert unblocked_entry["unblocked_at"] is not None


def test_invalid_ip_rejected():
    with pytest.raises(ValueError):
        block_ip("not-an-ip", "Invalid test")

    with pytest.raises(ValueError):
        block_ip("999.999.999.999", "Out of range")

    with pytest.raises(ValueError):
        block_ip("", "Empty IP")

    with pytest.raises(ValueError):
        unblock_ip("invalid-ip")

    # is_blocked fails open (returns False) on invalid input
    assert is_blocked("invalid-ip") is False
    assert is_blocked("") is False


def test_tcp_decoy_refuses_blocked_ip(monkeypatch):
    ip = "127.0.0.1"
    block_ip(ip, "TCP abuse test", "manual")

    captured_events = []
    def fake_log_event(source_ip, service, event_type, outcome, metadata):
        captured_events.append((source_ip, service, event_type, outcome, metadata))
    monkeypatch.setattr("honeypot.tcp_decoy.log_event", fake_log_event)

    srv, cli = socket.socketpair()
    thread = threading.Thread(target=handle_client, args=(srv, (ip, 54321)))
    thread.start()

    # Client receives EOF immediately (connection closed with no login prompt)
    data = cli.recv(1024)
    assert data == b""
    cli.close()
    thread.join(3)

    assert not thread.is_alive()
    # Exactly one event of type blocked_attempt logged and nothing else
    assert len(captured_events) == 1
    evt = captured_events[0]
    assert evt[0] == ip
    assert evt[1] == "tcp_login_decoy"
    assert evt[2] == "blocked_attempt"
    assert evt[3] == "blocked"


def test_http_decoy_returns_403_for_blocked_ip(monkeypatch):
    blocked_ip = "192.168.0.42"
    block_ip(blocked_ip, "Web scanner test", "manual")

    captured_events = []
    def fake_log_event(source_ip, service, event_type, outcome, metadata):
        captured_events.append((source_ip, service, event_type, outcome, metadata))
    monkeypatch.setattr("honeypot.http_decoy.log_event", fake_log_event)

    client = http_decoy_app.test_client()

    # Blocked IP request gets 403
    resp = client.get("/", environ_overrides={"REMOTE_ADDR": blocked_ip})
    assert resp.status_code == 403
    assert b"Blocked" in resp.data

    # Logged exactly one blocked_attempt event
    assert len(captured_events) == 1
    assert captured_events[0][0] == blocked_ip
    assert captured_events[0][2] == "blocked_attempt"

    # Non-blocked IP gets normal 200
    resp_ok = client.get("/", environ_overrides={"REMOTE_ADDR": "192.168.0.43"})
    assert resp_ok.status_code == 200


def test_blocked_events_ignored_by_rules():
    # A series of blocked_attempt events should not trigger any rule
    events = [
        {
            "id": i,
            "timestamp": f"2026-10-31T00:00:{i:02d}Z",
            "source_ip": "10.0.0.5",
            "service": "http_decoy",
            "event_type": "blocked_attempt",
            "outcome": "blocked",
            "metadata": {"suspicious": True},
        }
        for i in range(1, 30)
    ]
    detections = run_all(events)
    assert len(detections) == 0


def test_auto_block_on_high_incident(monkeypatch):
    set_setting("auto_block", "on")

    # Lab IP: should be auto-blocked when incident severity is high
    lab_ip = "192.168.1.99"
    # Insert high-severity COMBO-001 prerequisite events
    now_base = "2026-10-31T12:00:"
    # 5 login failures (AUTH-001) + 3 suspicious probes (COMBO-001)
    for i in range(config.AUTH_FAIL_COUNT):
        insert_event({
            "timestamp": f"{now_base}{i:02d}Z",
            "source_ip": lab_ip,
            "service": "tcp_login_decoy",
            "event_type": "login_attempt",
            "outcome": "simulated_failure",
            "metadata": {"username_length": 4, "password_length": 8},
        })
    for i in range(config.PROBE_COUNT):
        insert_event({
            "timestamp": f"{now_base}{10+i:02d}Z",
            "source_ip": lab_ip,
            "service": "http_decoy",
            "event_type": "http_request",
            "outcome": "404",
            "metadata": {"suspicious": True},
        })

    # Run worker loop
    worker.run_once()

    # Verify lab_ip was auto-blocked
    assert is_blocked(lab_ip) is True
    blocks = list_blocklist(active_only=True)
    b = next((x for x in blocks if x["ip"] == lab_ip), None)
    assert b is not None
    assert b["block_type"] == "auto"
    assert "COMBO-001" in b["reason"]

    # Non-lab IP (public IP e.g. 8.8.8.8) should NOT be auto-blocked
    public_ip = "8.8.8.8"
    for i in range(config.AUTH_FAIL_COUNT):
        insert_event({
            "timestamp": f"2026-10-31T12:01:{i:02d}Z",
            "source_ip": public_ip,
            "service": "tcp_login_decoy",
            "event_type": "login_attempt",
            "outcome": "simulated_failure",
            "metadata": {"username_length": 4, "password_length": 8},
        })
    for i in range(config.PROBE_COUNT):
        insert_event({
            "timestamp": f"2026-10-31T12:01:{10+i:02d}Z",
            "source_ip": public_ip,
            "service": "http_decoy",
            "event_type": "http_request",
            "outcome": "404",
            "metadata": {"suspicious": True},
        })

    worker.run_once()
    assert is_blocked(public_ip) is False


def test_clear_history_keeps_blocklist():
    # Setup blocks and settings
    block_ip("10.0.0.7", "Keep this block", "manual")
    set_setting("auto_block", "on")

    # Insert events and incidents
    ev_id = insert_event({
        "timestamp": "2026-10-31T00:00:00Z",
        "source_ip": "10.0.0.7",
        "service": "http_decoy",
        "event_type": "http_request",
        "outcome": "200",
        "metadata": {},
    })
    create_incident({
        "source_ip": "10.0.0.7",
        "start_time": "2026-10-31T00:00:00Z",
        "end_time": "2026-10-31T00:01:00Z",
        "severity": "low",
        "rule_ids": [],
        "event_ids": [ev_id],
    })

    assert count_table("events") == 1
    assert count_table("incidents") == 1

    # Clear history
    clear_history()

    # Events and incidents cleared
    assert count_table("events") == 0
    assert count_table("incidents") == 0

    # Blocklist and settings preserved
    assert is_blocked("10.0.0.7") is True
    assert get_setting("auto_block") == "on"
    assert len(list_blocklist(active_only=True)) == 1


def test_clear_history_web_route():
    from app import app as dashboard_app
    client = dashboard_app.test_client()

    insert_event({
        "timestamp": "2026-10-31T00:00:00Z",
        "source_ip": "10.0.0.8",
        "service": "http_decoy",
        "event_type": "http_request",
        "outcome": "200",
        "metadata": {},
    })
    assert count_table("events") == 1

    # Form submission from browser redirects back
    resp = client.post("/clear-history", headers={"Referer": "/"})
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/"
    assert count_table("events") == 0

    # JSON API call returns json status
    insert_event({
        "timestamp": "2026-10-31T00:00:01Z",
        "source_ip": "10.0.0.8",
        "service": "http_decoy",
        "event_type": "http_request",
        "outcome": "200",
        "metadata": {},
    })
    resp_json = client.post("/clear-history", json={}, headers={"Accept": "application/json"})
    assert resp_json.status_code == 200
    assert resp_json.get_json() == {"status": "cleared"}
    assert count_table("events") == 0


def test_worker_watermark_resets_after_clear():
    # Insert event
    id1 = insert_event({
        "timestamp": "2026-10-31T00:00:00Z",
        "source_ip": "10.0.0.9",
        "service": "tcp_login_decoy",
        "event_type": "login_attempt",
        "outcome": "failed",
        "metadata": {},
    })
    worker._last_event_id = id1

    # Clear history
    clear_history()

    # Worker runs when db is empty -> resets watermark to 0
    worker.run_once()
    assert worker._last_event_id == 0

    # New event inserted after clear
    id2 = insert_event({
        "timestamp": "2026-10-31T00:00:01Z",
        "source_ip": "10.0.0.9",
        "service": "tcp_login_decoy",
        "event_type": "login_attempt",
        "outcome": "failed",
        "metadata": {},
    })
    # Worker runs again -> picks up new event
    worker.run_once()
    assert worker._last_event_id == id2


def test_http_decoy_server_banner_morphing():
    from honeypot.http_decoy import SERVER_BANNERS

    client = http_decoy_app.test_client()
    seen_banners = set()

    for _ in range(25):
        resp = client.get("/", environ_overrides={"REMOTE_ADDR": "127.0.0.1"})
        assert resp.status_code == 200
        server_header = resp.headers.get("Server")
        assert server_header in SERVER_BANNERS
        seen_banners.add(server_header)

    # Dynamic morphing should produce more than 1 distinct server banner across 25 requests
    assert len(seen_banners) > 1

    # Check that 404 responses also receive a morphed banner
    resp_404 = client.get("/nonexistent-page", environ_overrides={"REMOTE_ADDR": "127.0.0.1"})
    assert resp_404.status_code == 404
    assert resp_404.headers.get("Server") in SERVER_BANNERS


def test_get_recent_deceptive_events():
    from database.db import get_recent_deceptive_events
    client = http_decoy_app.test_client()

    client.get("/", environ_overrides={"REMOTE_ADDR": "127.0.0.1"})
    client.get("/admin", environ_overrides={"REMOTE_ADDR": "127.0.0.1"})

    evs = get_recent_deceptive_events(limit=5)
    assert len(evs) >= 2
    for ev in evs:
        assert ev["service"] == "http_decoy"
        assert "server_banner" in ev["metadata"]

