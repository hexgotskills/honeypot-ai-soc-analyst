import datetime
import config
from detection.scoring import SEVERITY

def to_seconds(ts):
    return datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc).timestamp()

def find_burst(events, count, seconds):
    # events assumed sorted by timestamp
    n = len(events)
    for i in range(n - count + 1):
        start = to_seconds(events[i]["timestamp"])
        end = to_seconds(events[i + count - 1]["timestamp"])
        if end - start <= seconds:
            return events[i:i + count]
    return None

def run_all(events):
    # Exclude blocked_attempt events from every rule
    events = [e for e in events if e.get("event_type") != "blocked_attempt"]
    # group by source_ip
    by_ip = {}
    for ev in events:
        by_ip.setdefault(ev["source_ip"], []).append(ev)
    detections = []
    now_ts = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat() + "Z"
    for src, evlist in by_ip.items():
        evlist.sort(key=lambda e: e["timestamp"])
        # AUTH-001
        auth_ev = [e for e in evlist if e["event_type"] == "login_attempt" and e["outcome"] == "simulated_failure"]
        auth_burst = find_burst(auth_ev, config.AUTH_FAIL_COUNT, config.AUTH_WINDOW)
        auth_ids = []
        if auth_burst:
            auth_ids = [e["id"] for e in auth_burst]
            detections.append({
                "rule_id": "AUTH-001",
                "rule_name": "Repeated login failures",
                "source_ip": src,
                "event_ids": auth_ids,
                "match_count": len(auth_ids),
                "window_seconds": config.AUTH_WINDOW,
                "reason": f"{len(auth_ids)} failed simulated logins from one source within {config.AUTH_WINDOW} seconds",
                "severity": "medium",
                "detected_at": now_ts,
                "unique_key": f"AUTH-001|{src}|{auth_ids[0]}",
            })
        # WEB-001
        web_ev = [e for e in evlist if e["event_type"] in ("http_request", "decoy_resource_access")]
        web_burst = find_burst(web_ev, config.WEB_RATE_COUNT, config.WEB_RATE_WINDOW)
        if web_burst:
            ids = [e["id"] for e in web_burst]
            detections.append({
                "rule_id": "WEB-001",
                "rule_name": "Rapid request activity",
                "source_ip": src,
                "event_ids": ids,
                "match_count": len(ids),
                "window_seconds": config.WEB_RATE_WINDOW,
                "reason": f"{len(ids)} HTTP events from one source within {config.WEB_RATE_WINDOW} seconds",
                "severity": "medium",
                "detected_at": now_ts,
                "unique_key": f"WEB-001|{src}|{ids[0]}",
            })
        # WEB-002
        decoy_ev = [e for e in evlist if e["event_type"] == "decoy_resource_access"]
        if decoy_ev:
            first = decoy_ev[0]
            detections.append({
                "rule_id": "WEB-002",
                "rule_name": "Decoy resource access",
                "source_ip": src,
                "event_ids": [first["id"]],
                "match_count": 1,
                "window_seconds": 0,
                "reason": "Decoy resource accessed",
                "severity": "medium",
                "detected_at": now_ts,
                "unique_key": f"WEB-002|{src}|{first["id"]}",
            })
        # COMBO-001
        if auth_burst:
            probe_ev = [e for e in evlist if e.get('metadata', {}).get('suspicious')]
            probe_burst = find_burst(probe_ev, config.PROBE_COUNT, config.COMBO_WINDOW)
            if probe_burst:
                probe_ids = [e["id"] for e in probe_burst]
                detections.append({
                    "rule_id": "COMBO-001",
                    "rule_name": "Combined activity",
                    "source_ip": src,
                    "event_ids": auth_ids + probe_ids,
                    "match_count": len(auth_ids) + len(probe_ids),
                    "window_seconds": config.COMBO_WINDOW,
                    "reason": "Failed logins and suspicious probes within window",
                    "severity": "high",
                    "detected_at": now_ts,
                    "unique_key": f"COMBO-001|{src}|{auth_ids[0]}",
                })
    return detections
