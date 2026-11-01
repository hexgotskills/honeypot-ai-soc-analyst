import os
import json
import sqlite3
import datetime
import ipaddress
import config

# Helper to get a connection. Ensures the folder for the DB exists and uses WAL mode.
def get_connection():
    # Make sure the directory for the DB file exists.
    os.makedirs(os.path.dirname(config.DATABASE_PATH), exist_ok=True)
    conn = sqlite3.connect(config.DATABASE_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    # Enable WAL so multiple processes can use the same DB safely.
    conn.execute('PRAGMA journal_mode=WAL')
    return conn

# Run the schema script to create tables.
def initialize_database():
    conn = get_connection()
    try:
        # Build path to schema.sql relative to this file.
        schema_path = os.path.join(os.path.dirname(__file__), 'schema.sql')
        with open(schema_path, 'r', encoding='utf-8') as f:
            script = f.read()
        conn.executescript(script)
    finally:
        conn.close()

# Helper to turn a sqlite3.Row into a plain dict and decode metadata.
def row_to_event(row):
    event = dict(row)
    # Convert JSON string back to dict.
    meta = event.get('metadata_json')
    if meta:
        try:
            event['metadata'] = json.loads(meta)
        except Exception:
            event['metadata'] = {}
    else:
        event['metadata'] = {}
    # Remove the raw JSON column from output.
    event.pop('metadata_json', None)
    return event

def insert_event(event):
    # event is a dict with required keys.
    conn = get_connection()
    try:
        cur = conn.cursor()
        # Use parameterized query to avoid SQL injection.
        cur.execute(
            "INSERT INTO events (timestamp, source_ip, service, event_type, outcome, metadata_json) VALUES (?, ?, ?, ?, ?, ?)",
            (
                event['timestamp'],
                event['source_ip'],
                event['service'],
                event['event_type'],
                event.get('outcome'),
                json.dumps(event.get('metadata', {})),
            ),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()

def get_recent_events(limit=50):
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
        rows = cur.fetchall()
        return [row_to_event(r) for r in rows]
    finally:
        conn.close()

def get_events_by_source(source_ip):
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM events WHERE source_ip = ? ORDER BY id ASC", (source_ip,))
        rows = cur.fetchall()
        return [row_to_event(r) for r in rows]
    finally:
        conn.close()

def get_events_after(last_id):
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM events WHERE id > ? ORDER BY id ASC", (last_id,))
        rows = cur.fetchall()
        return [row_to_event(r) for r in rows]
    finally:
        conn.close()

def create_incident(incident):
    conn = get_connection()
    try:
        cur = conn.cursor()
        # Insert incident row.
        cur.execute(
            "INSERT INTO incidents (source_ip, start_time, end_time, severity, rule_ids) VALUES (?, ?, ?, ?, ?)",
            (
                incident['source_ip'],
                incident['start_time'],
                incident['end_time'],
                incident['severity'],
                json.dumps(incident.get('rule_ids', [])),
            ),
        )
        incident_id = cur.lastrowid
        # Link event ids.
        for ev_id in incident.get('event_ids', []):
            cur.execute("INSERT INTO incident_events (incident_id, event_id) VALUES (?, ?)", (incident_id, ev_id))
        conn.commit()
        return incident_id
    finally:
        conn.close()

def get_incident(incident_id):
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
        inc_row = cur.fetchone()
        if not inc_row:
            return None
        incident = dict(inc_row)
        # Load rule_ids JSON.
        if incident.get('rule_ids'):
            try:
                incident['rule_ids'] = json.loads(incident['rule_ids'])
            except Exception:
                incident['rule_ids'] = []
        else:
            incident['rule_ids'] = []
        # Get linked event ids.
        cur.execute("SELECT event_id FROM incident_events WHERE incident_id = ?", (incident_id,))
        rows = cur.fetchall()
        incident['event_ids'] = [r['event_id'] for r in rows]
        return incident
    finally:
        conn.close()

# Additional DB helpers for detections, correlation, AI reports, stats

def save_detection(d):
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT OR IGNORE INTO detections "
            "(unique_key, rule_id, rule_name, source_ip, event_ids, match_count, window_seconds, reason, severity, detected_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                d.get('unique_key'),
                d.get('rule_id'),
                d.get('rule_name', ''),
                d.get('source_ip'),
                json.dumps(d.get('event_ids', [])),
                d.get('match_count', 0),
                d.get('window_seconds', 0),
                d.get('reason', ''),
                d.get('severity'),
                d.get('detected_at'),
            ),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()

def get_events_since(seconds):
    cutoff = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=seconds)).replace(microsecond=0).isoformat() + "Z"
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM events WHERE timestamp>=? ORDER BY timestamp ASC", (cutoff,))
        rows = cur.fetchall()
        return [row_to_event(r) for r in rows]
    finally:
        conn.close()

def get_events_by_ids(ids):
    if not ids:
        return []
    placeholders = ",".join(["?"]*len(ids))
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(f"SELECT * FROM events WHERE id IN ({placeholders}) ORDER BY timestamp ASC", ids)
        rows = cur.fetchall()
        return [row_to_event(r) for r in rows]
    finally:
        conn.close()

def get_latest_incident_for_source(source_ip):
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM incidents WHERE source_ip=? ORDER BY end_time DESC LIMIT 1", (source_ip,))
        row = cur.fetchone()
        if not row:
            return None
        inc = dict(row)
        inc['rule_ids'] = json.loads(inc.get('rule_ids') or "[]")
        cur.execute("SELECT event_id FROM incident_events WHERE incident_id=?", (inc['id'],))
        inc['event_ids'] = [r['event_id'] for r in cur.fetchall()]
        return inc
    finally:
        conn.close()

def update_incident(incident_id, end_time, severity, rule_ids, event_ids):
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE incidents SET end_time=?, severity=?, rule_ids=? WHERE id=?",
            (end_time, severity, json.dumps(rule_ids), incident_id),
        )
        for ev in event_ids:
            cur.execute(
                "INSERT OR IGNORE INTO incident_events (incident_id, event_id) VALUES (?,?)",
                (incident_id, ev),
            )
        conn.commit()
    finally:
        conn.close()


def get_incidents(limit):
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM incidents ORDER BY end_time DESC LIMIT ?", (limit,))
        rows = cur.fetchall()
        incidents = []
        for r in rows:
            inc = dict(r)
            inc['rule_ids'] = json.loads(inc.get('rule_ids') or "[]")
            cur.execute("SELECT event_id FROM incident_events WHERE incident_id=?", (inc['id'],))
            inc['event_ids'] = [e['event_id'] for e in cur.fetchall()]
            incidents.append(inc)
        return incidents
    finally:
        conn.close()

def get_detections_by_source(source_ip):
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM detections WHERE source_ip=?", (source_ip,))
        rows = cur.fetchall()
        dets = []
        for r in rows:
            d = dict(r)
            d['event_ids'] = json.loads(d.get('event_ids') or "[]")
            dets.append(d)
        return dets
    finally:
        conn.close()

def save_ai_report(incident_id, status, report_json):
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM ai_reports WHERE incident_id=?", (incident_id,))
        exists = cur.fetchone()
        rpt = json.dumps(report_json) if report_json is not None else None
        if exists:
            cur.execute(
                "UPDATE ai_reports SET status=?, report_json=? WHERE incident_id=?",
                (status, rpt, incident_id),
            )
        else:
            cur.execute(
                "INSERT INTO ai_reports (incident_id, status, report_json) VALUES (?,?,?)",
                (incident_id, status, rpt),
            )
        conn.commit()
    finally:
        conn.close()


def get_ai_report(incident_id):
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT status, report_json FROM ai_reports WHERE incident_id=?", (incident_id,))
        row = cur.fetchone()
        if not row:
            return None
        status, rpt = row[0], row[1]
        return {'status': status, 'report': json.loads(rpt) if rpt else None}
    finally:
        conn.close()

def save_analysis(event_ids, provider, report):
    """Save a multi-event analysis to the analyses table.
    event_ids: list of int IDs
    provider: string (e.g. 'mock', 'gemini')
    report: dict or JSON string
    Returns: new analysis ID (int)
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        ev_json = json.dumps(event_ids) if not isinstance(event_ids, str) else event_ids
        rpt_json = json.dumps(report) if not isinstance(report, str) else report
        cur.execute(
            "INSERT INTO analyses (event_ids, provider, report_json) VALUES (?, ?, ?)",
            (ev_json, provider, rpt_json),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()

def get_analysis(analysis_id):
    """Fetch an analysis record by ID.
    Returns dict with keys: id, created_at, event_ids, provider, report.
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, created_at, event_ids, provider, report_json FROM analyses WHERE id=?", (analysis_id,))
        row = cur.fetchone()
        if not row:
            return None
        ev_ids = json.loads(row["event_ids"]) if row["event_ids"] else []
        rpt = json.loads(row["report_json"]) if row["report_json"] else {}
        return {
            "id": row["id"],
            "created_at": row["created_at"],
            "event_ids": ev_ids,
            "provider": row["provider"],
            "report": rpt,
        }
    finally:
        conn.close()

def list_analyses(limit=50):
    """List recent saved analyses ordered by ID descending."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, created_at, event_ids, provider, report_json FROM analyses ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        rows = cur.fetchall()
        results = []
        for row in rows:
            ev_ids = json.loads(row["event_ids"]) if row["event_ids"] else []
            rpt = json.loads(row["report_json"]) if row["report_json"] else {}
            results.append({
                "id": row["id"],
                "created_at": row["created_at"],
                "event_ids": ev_ids,
                "provider": row["provider"],
                "report": rpt,
            })
        return results
    finally:
        conn.close()

def count_table(name):
    if name not in ('events','detections','incidents','analyses'):
        raise ValueError('Invalid table name')
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(f"SELECT COUNT(*) FROM {name}")
        return cur.fetchone()[0]
    finally:
        conn.close()

def count_incidents_by_severity():
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT severity, COUNT(*) FROM incidents GROUP BY severity")
        rows = cur.fetchall()
        result = {'low':0,'medium':0,'high':0}
        for sev, cnt in rows:
            result[sev] = cnt
        return result
    finally:
        conn.close()

# ---------- Stats helpers (Phase 2) ----------

def get_events_per_minute_last_30():
    """Return list of (minute_iso, count) for the last 30 minutes.
    minute_iso is ISO string truncated to minute, e.g. '2023-01-01T12:34Z'."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT substr(timestamp, 1, 16) || 'Z' AS minute, COUNT(*) AS cnt
            FROM events
            WHERE timestamp >= datetime('now', '-30 minutes')
            GROUP BY minute
            ORDER BY minute ASC;
            """
        )
        rows = cur.fetchall()
        return [(r['minute'], r['cnt']) for r in rows]
    finally:
        conn.close()

def get_events_by_type_counts():
    """Return dict mapping event_type to count for all events."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT event_type, COUNT(*) AS cnt FROM events GROUP BY event_type")
        rows = cur.fetchall()
        return {r['event_type']: r['cnt'] for r in rows}
    finally:
        conn.close()

def clear_history():
    """Delete all events, detections, incidents, incident_events, ai_reports.
    Reset SQLite autoincrement counters for those tables.
    Blocklist and settings are preserved.
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        # Delete data
        cur.executescript('''
            DELETE FROM events;
            DELETE FROM detections;
            DELETE FROM incidents;
            DELETE FROM incident_events;
            DELETE FROM ai_reports;
            DELETE FROM analyses;
        ''')
        # Reset autoincrement counters (sqlite_sequence)
        cur.execute("DELETE FROM sqlite_sequence WHERE name IN ('events','detections','incidents','incident_events','ai_reports','analyses')")
        conn.commit()
    finally:
        conn.close()


def get_incidents_by_severity_counts():
    """Return dict mapping severity (low, medium, high) to incident counts."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT severity, COUNT(*) AS cnt FROM incidents GROUP BY severity")
        rows = cur.fetchall()
        return {r['severity']: r['cnt'] for r in rows}
    finally:
        conn.close()

def get_last_event_time_by_service():
    """Return dict mapping service name to latest event timestamp (ISO string)."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT service, MAX(timestamp) AS latest FROM events GROUP BY service
            """
        )
        rows = cur.fetchall()
        return {r['service']: r['latest'] for r in rows}
    finally:
        conn.close()

def get_top_source_ips(limit=5):
    """Return list of (source_ip, count) for top source IPs by event count."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT source_ip, COUNT(*) AS cnt FROM events GROUP BY source_ip ORDER BY cnt DESC LIMIT ?",
            (limit,)
        )
        rows = cur.fetchall()
        return [(r['source_ip'], r['cnt']) for r in rows]
    finally:
        conn.close()

def get_detection_counts_by_rule():
    """Return dict mapping rule_id to detection count."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT rule_id, COUNT(*) AS cnt FROM detections GROUP BY rule_id")
        rows = cur.fetchall()
        return {r['rule_id']: r['cnt'] for r in rows}
    finally:
        conn.close()

def get_incident_id_for_event(event_id):
    """Return the incident_id linked to the given event_id, or None."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT incident_id FROM incident_events WHERE event_id = ? LIMIT 1", (event_id,))
        row = cur.fetchone()
        return row['incident_id'] if row else None
    finally:
        conn.close()

def get_detections_for_event(event_id):
    """Return list of detections that match the given event_id."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM detections WHERE event_ids LIKE ?", (f"%{event_id}%",))
        rows = cur.fetchall()
        matches = []
        for r in rows:
            d = dict(r)
            try:
                eids = json.loads(d.get('event_ids') or '[]')
            except Exception:
                eids = []
            if event_id in eids:
                matches.append(d)
        return matches
    finally:
        conn.close()

# ---------------------------------------------------------------------------
# Blocklist helpers
# NOTE: This is an application-level block only, not an operating system firewall.
# ---------------------------------------------------------------------------

def _validate_ip(ip: str) -> bool:
    """Return True if *ip* is a syntactically valid IPv4 or IPv6 address.
    Raises ValueError with a clear message for the caller.
    """
    if not isinstance(ip, str) or not ip.strip():
        raise ValueError("Invalid IP address: empty or non-string input")
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except Exception as exc:
        raise ValueError(f"Invalid IP address '{ip}': {exc}")

def block_ip(ip: str, reason: str, block_type: str = "manual"):
    """Insert or reactivate a block entry.
    *block_type* must be 'manual' or 'auto'.
    Returns the row id.
    """
    _validate_ip(ip)
    clean_ip = ip.strip()
    if block_type not in ("manual", "auto"):
        raise ValueError("block_type must be 'manual' or 'auto'")
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO blocklist (ip, reason, block_type, active, unblocked_at) "
            "VALUES (?, ?, ?, 1, NULL) "
            "ON CONFLICT(ip) DO UPDATE SET reason=excluded.reason, block_type=excluded.block_type, active=1, unblocked_at=NULL",
            (clean_ip, reason, block_type),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()

def unblock_ip(ip: str):
    """Mark a block as inactive and set *unblocked_at* timestamp.
    Returns the number of rows updated (0 if not present or already inactive).
    """
    _validate_ip(ip)
    clean_ip = ip.strip()
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE blocklist SET active = 0, unblocked_at = CURRENT_TIMESTAMP WHERE ip = ? AND active = 1",
            (clean_ip,)
        )
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()

def is_blocked(ip: str) -> bool:
    """Return True if *ip* has an active block entry.
    Application-level check.
    If the check fails due to database error, treat as not blocked and print a warning.
    """
    try:
        _validate_ip(ip)
    except ValueError:
        return False
    clean_ip = ip.strip()
    try:
        conn = get_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT 1 FROM blocklist WHERE ip = ? AND active = 1", (clean_ip,))
            return cur.fetchone() is not None
        finally:
            conn.close()
    except Exception as e:
        print(f"[WARN] blocklist check failed: {e}")
        return False

def list_blocklist(active_only: bool = True):
    """Return a list of dicts representing blocklist rows.
    If *active_only* is True, only rows with active = 1 are returned.
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        if active_only:
            cur.execute("SELECT * FROM blocklist WHERE active = 1 ORDER BY id DESC")
        else:
            cur.execute("SELECT * FROM blocklist ORDER BY id DESC")
        rows = cur.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

# ---------------------------------------------------------------------------
# Settings helpers
# ---------------------------------------------------------------------------

def get_setting(key: str, default: str = None) -> str:
    """Fetch setting by key from settings table. Returns default if not found."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT value FROM settings WHERE key = ?", (key,))
        row = cur.fetchone()
        return row['value'] if row else default
    finally:
        conn.close()

def set_setting(key: str, value: str):
    """Save or update setting key=value."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(value)),
        )
        conn.commit()
    finally:
        conn.close()


def get_recent_deceptive_events(limit: int = 10):
    """Fetch recent HTTP decoy events with deceptive server banner assignments."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM events WHERE service = 'http_decoy' ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        rows = cur.fetchall()
        return [row_to_event(r) for r in rows]
    finally:
        conn.close()
