"""
worker.py – background loop for the Honeypot AI SOC.

Each iteration (run_once):
1. Fetch events added since the last check.
2. Run detection rules on those events.
3. Save new detections to the database.
4. Correlate detections into incidents.
"""
import time

from database.db import (
    initialize_database,
    get_events_after,
    save_detection,
    get_ai_report,
    get_setting,
    block_ip,
    is_blocked,
    get_incident,
)
from honeypot.event_logger import log_event
import ipaddress
from detection.rules import run_all
from detection.correlation import correlate
from analyst.report_builder import generate_report


LAB_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("10.0.0.0/8"),
]

def is_lab_ip(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str.strip())
        return any(addr in net for net in LAB_NETWORKS)
    except Exception:
        return False

# Track the last event id we processed so we only look at new events each loop.
_last_event_id = 0


def run_once():
    """Fetch new events, detect, correlate, and write heartbeat."""
    global _last_event_id
    # 1. Get events added since last run.
    new_events = get_events_after(_last_event_id)
    if not new_events:
        # Check if events table was cleared or reset so watermark stays synchronized
        try:
            from database.db import get_connection
            conn = get_connection()
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*), MAX(id) FROM events")
            cnt, max_id = cur.fetchone()
            conn.close()
            if cnt == 0 or (_last_event_id and (max_id is None or _last_event_id > max_id)):
                _last_event_id = 0
        except Exception:
            pass
        _write_heartbeat()
        return

    print(f"[worker] cycle: {len(new_events)} events read", flush=True)

    # Skip blocked_attempt events – they should not generate detections or incidents
    filtered_events = [e for e in new_events if e.get('event_type') != 'blocked_attempt']

    # Update watermark using all events (including blocked) to avoid re‑processing them.
    _last_event_id = max(e["id"] for e in new_events)

    # 2. Run detection rules.
    detections = run_all(filtered_events)

    # 3. Save each new detection (duplicates are silently ignored via unique_key).
    saved = []
    for d in detections:
        if save_detection(d):
            saved.append(d)
            print(f"[worker] {d['rule_id']} fired for {d['source_ip']}", flush=True)

    # 4. Correlate saved detections into incidents.
    if saved:
        incident_ids = correlate(saved)
        for inc_id in incident_ids:
            inc = get_incident(inc_id)
            sev = inc.get("severity", "unknown") if inc else "unknown"
            print(f"[worker] incident {inc_id} created, severity {sev}", flush=True)
            # 5. Run AI analysis for incidents that don't have a report yet.
            try:
                if get_ai_report(inc_id) is None:
                    generate_report(inc_id)
            except Exception as e:
                print(f"[worker] analyst error for incident {inc_id}: {e}", flush=True)
        # ----- Auto‑block feature -----
        auto_block = get_setting('auto_block', 'off')
        if auto_block and auto_block.lower() == 'on':
            blocked_in_batch = set()
            for inc_id in incident_ids:
                inc = get_incident(inc_id)
                if not inc or inc.get('severity') != 'high':
                    continue
                src_ip = inc.get('source_ip')
                if not src_ip or src_ip in blocked_in_batch:
                    continue
                # Only lab addresses (127.0.0.0/8, 192.168.0.0/16, 10.0.0.0/8)
                if not is_lab_ip(src_ip):
                    continue
                if is_blocked(src_ip):
                    continue
                rule_str = ", ".join(inc.get("rule_ids", []))
                reason = f"Auto-blocked: incident {inc_id} (high severity, rules: {rule_str})"
                block_ip(src_ip, reason, block_type="auto")
                blocked_in_batch.add(src_ip)
                print(f"[worker] auto-blocked {src_ip}", flush=True)
    # Write heartbeat after processing
    _write_heartbeat()

def _write_heartbeat():
    """Write current UTC timestamp to data/worker_heartbeat file."""
    import os, datetime
    hb_path = os.path.join(os.path.dirname(__file__), 'data', 'worker_heartbeat')
    os.makedirs(os.path.dirname(hb_path), exist_ok=True)
    with open(hb_path, 'w', encoding='utf-8') as f:
        f.write(datetime.datetime.now(datetime.timezone.utc).isoformat())


if __name__ == "__main__":
    initialize_database()
    print("[worker] worker started", flush=True)
    while True:
        try:
            run_once()
        except Exception as e:
            print(f"[worker] error: {e}", flush=True)
        time.sleep(5)
