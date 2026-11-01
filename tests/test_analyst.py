import json
import pytest
import requests
import config
from database.db import (
    initialize_database,
    insert_event,
    create_incident,
    get_ai_report,
    get_analysis,
    list_analyses,
)
from analyst.validation import validate_report
from analyst.report_builder import generate_report
from app import app

GOOD_REPORT = {
    "summary": "Automated analysis identified suspicious traffic from source IP 1.2.3.4 targeting decoy services. Repeated login failures were detected matching authentication rules.",
    "technical_analysis": "The incoming connections repeatedly attempted authentication on the decoy TCP service. Detection rule AUTH-001 triggered based on threshold failures within the observation window. The events connect in sequence as an automated brute-force attempt.",
    "attack_stage": "credential access",
    "attack_technique": "T1110 - Brute Force",
    "evidence": [
        {"event_id": 1, "note": "Failed login attempt recorded"},
        {"event_id": 2, "note": "Subsequent failed login attempt recorded"}
    ],
    "confidence": "low - Based on simulated lab telemetry without external correlation.",
    "recommended_actions": [
        "Block the source IP at perimeter firewall.",
        "Review authentication logs across services.",
        "Ensure decoy endpoints remain isolated."
    ],
    "false_positive_notes": "Decoy endpoints have no legitimate users, minimizing false positives.",
    "limitations": "Analysis is based strictly on local honeypot telemetry.",
    "severity": "low",
}

@pytest.fixture(autouse=True)
def tmp_db(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", str(tmp_path / "test.db"))
    initialize_database()

@pytest.fixture()
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

@pytest.fixture()
def incident_id():
    e1 = insert_event({
        "timestamp": "2026-10-31T00:00:00Z",
        "source_ip": "1.2.3.4",
        "service": "tcp",
        "event_type": "login_attempt",
        "outcome": "simulated_failure",
        "metadata": {},
    })
    e2 = insert_event({
        "timestamp": "2026-10-31T00:00:01Z",
        "source_ip": "1.2.3.4",
        "service": "tcp",
        "event_type": "login_attempt",
        "outcome": "simulated_failure",
        "metadata": {},
    })
    return create_incident({
        "source_ip": "1.2.3.4",
        "start_time": "2026-10-31T00:00:00Z",
        "end_time": "2026-10-31T00:00:01Z",
        "severity": "low",
        "rule_ids": ["AUTH-001"],
        "event_ids": [e1, e2],
    })

def test_validate_good_report():
    report, err = validate_report(
        json.dumps(GOOD_REPORT),
        allowed_event_ids=[1, 2],
        allowed_rule_ids=["AUTH-001"],
        expected_severity="low",
    )
    assert err is None
    assert "credential access" in report["attack_stage"]
    assert report["severity"] == "low"

def test_validate_rejects_fake_event_id():
    bad = dict(GOOD_REPORT)
    bad["evidence"] = [{"event_id": 999, "note": "fake event"}]
    report, err = validate_report(json.dumps(bad), allowed_event_ids=[1, 2])
    assert report is None
    assert err is not None
    assert "999" in err

def test_validate_rejects_fake_rule_id():
    bad = dict(GOOD_REPORT)
    bad["evidence"] = [{"rule_id": "RULE-999", "note": "fake rule"}]
    report, err = validate_report(
        json.dumps(bad),
        allowed_event_ids=[1, 2],
        allowed_rule_ids=["AUTH-001"],
    )
    assert report is None
    assert err is not None
    assert "RULE-999" in err

def test_validate_rejects_wrong_severity():
    bad = dict(GOOD_REPORT)
    bad["severity"] = "high"
    report, err = validate_report(
        json.dumps(bad),
        allowed_event_ids=[1, 2],
        expected_severity="low",
    )
    assert report is None
    assert err is not None
    assert "severity" in err.lower()

def test_validate_rejects_missing_field():
    bad = dict(GOOD_REPORT)
    del bad["technical_analysis"]
    report, err = validate_report(json.dumps(bad), allowed_event_ids=[1, 2])
    assert report is None
    assert err is not None
    assert "technical_analysis" in err

def test_validate_rejects_non_json():
    report, err = validate_report("not json at all", allowed_event_ids=[1, 2])
    assert report is None
    assert err is not None

def test_generate_report_mock_saves_done(monkeypatch, incident_id):
    monkeypatch.setattr(config, "AI_PROVIDER", "mock")
    generate_report(incident_id)
    r = get_ai_report(incident_id)
    assert r is not None
    assert r["status"] == "done"
    assert "summary" in r["report"]
    assert "technical_analysis" in r["report"]
    assert "attack_stage" in r["report"]
    assert len(r["report"]["recommended_actions"]) >= 3

def test_generate_report_gemini_no_key_saves_not_configured(monkeypatch, incident_id):
    monkeypatch.setattr(config, "AI_PROVIDER", "gemini")
    monkeypatch.setattr(config, "AI_API_KEY", "")
    generate_report(incident_id)
    r = get_ai_report(incident_id)
    assert r is not None
    assert r["status"] == "not_configured"

def test_fallback_on_simulated_api_error(monkeypatch, incident_id):
    monkeypatch.setattr(config, "AI_PROVIDER", "gemini")
    monkeypatch.setattr(config, "AI_API_KEY", "dummy_key")

    def mock_post_fail(*args, **kwargs):
        raise requests.RequestException("Simulated connection timeout to Gemini API")

    monkeypatch.setattr(requests, "post", mock_post_fail)

    # Should not raise exception or crash
    generate_report(incident_id)
    r = get_ai_report(incident_id)
    assert r is not None
    assert r["status"] == "fallback"
    assert "ai_error" in r["report"]
    assert "Simulated connection timeout" in r["report"]["ai_error"]
    # Fallback report is still fully structured
    assert "summary" in r["report"]
    assert "technical_analysis" in r["report"]
    assert len(r["report"]["recommended_actions"]) >= 3

def test_multi_event_route_1_id(client):
    eid = insert_event({
        "timestamp": "2026-10-31T01:00:00Z",
        "source_ip": "10.0.0.5",
        "service": "http",
        "event_type": "http_request",
        "outcome": "200_ok",
        "metadata": {"path": "/index.html"},
    })

    # Test form submission with 1 id
    resp = client.post("/analyze-events", data={"event_ids": [eid]})
    assert resp.status_code == 302
    assert "/analysis/" in resp.headers["Location"]

    analyses = list_analyses()
    assert len(analyses) == 1
    assert analyses[0]["event_ids"] == [eid]

def test_multi_event_route_5_ids(client):
    eids = []
    for i in range(5):
        e = insert_event({
            "timestamp": f"2026-10-31T01:00:0{i}Z",
            "source_ip": f"10.0.0.{i+1}",
            "service": "tcp",
            "event_type": "login_attempt",
            "outcome": "simulated_failure",
            "metadata": {},
        })
        eids.append(e)

    # Test JSON submission with 5 ids
    resp = client.post(
        "/analyze-events",
        json={"event_ids": eids},
        headers={"Accept": "application/json"},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "ok"
    assert "id" in data
    assert "report" in data
    assert data["report"]["attack_stage"] in ("credential access", "multi-stage")

def test_multi_event_route_101_ids(client):
    # 101 event IDs should be rejected with 400
    ids_101 = list(range(1, 102))
    resp = client.post("/analyze-events", json={"event_ids": ids_101})
    assert resp.status_code == 400
    data = resp.get_json()
    assert "exceeds" in data["error"].lower() or "limit" in data["error"].lower()

def test_analyses_saved_and_listed(client):
    # Create 2 events and analyze them
    e1 = insert_event({
        "timestamp": "2026-10-31T02:00:00Z",
        "source_ip": "192.168.1.50",
        "service": "http",
        "event_type": "decoy_resource_access",
        "outcome": "decoy_triggered",
        "metadata": {"path": "/admin/backup.sql"},
    })
    e2 = insert_event({
        "timestamp": "2026-10-31T02:00:05Z",
        "source_ip": "192.168.1.51",
        "service": "http",
        "event_type": "decoy_resource_access",
        "outcome": "decoy_triggered",
        "metadata": {"path": "/admin/config.php"},
    })

    resp = client.post("/analyze-events", data={"event_ids": [e1, e2]}, follow_redirects=True)
    assert resp.status_code == 200
    # Checks that analysis detail page renders cleanly with no emojis
    assert b"Multi-Event Analysis" in resp.data
    assert b"Summary" in resp.data
    assert b"Technical Analysis" in resp.data
    assert b"Recommended Actions" in resp.data

    # Check analyses list page
    resp_list = client.get("/analyses")
    assert resp_list.status_code == 200
    assert b"Saved Multi-Event Analyses" in resp_list.data
    assert b"2 events" in resp_list.data

def test_incident_analyze_route(client, incident_id):
    # Existing route POST /incident/<incident_id>/analyze
    resp = client.post(f"/incident/{incident_id}/analyze")
    assert resp.status_code == 302
    assert f"/incident/{incident_id}" in resp.headers["Location"]

    # Follow redirect to view rendered report on incident page
    detail = client.get(f"/incident/{incident_id}")
    assert detail.status_code == 200
    assert b"Summary" in detail.data
    assert b"Technical Analysis" in detail.data
    assert b"Attack Stage" in detail.data


