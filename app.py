"""
app.py – Flask web dashboard for the Honeypot AI SOC.

Routes:
  GET /             – Main dashboard (events + incidents summary).
  GET /incident/<id> – Detail page for one incident.
  GET /api/events   – JSON list of recent events (last 50).
  GET /api/incidents – JSON list of recent incidents (last 20).
"""
from flask import Flask, render_template, jsonify, abort, redirect, url_for, request
import config
from database.db import (
    initialize_database,
    get_recent_events,
    get_incidents,
    get_incident,
    get_events_by_ids,
    count_table,
    count_incidents_by_severity,
    get_ai_report,
    # new stats helpers
    get_events_per_minute_last_30,
    get_events_by_type_counts,
    get_incidents_by_severity_counts,
    get_top_source_ips,
    get_detection_counts_by_rule,
    # blocklist and countermeasures
    get_setting,
    set_setting,
    block_ip,
    unblock_ip,
    is_blocked,
    list_blocklist,
    # analyses
    save_analysis,
    get_analysis,
    list_analyses,
    get_recent_deceptive_events,
)

from analyst.report_builder import generate_report, analyze_events

app = Flask(__name__)


@app.route("/")
def index():
    events = get_recent_events(limit=50)
    incidents = get_incidents(limit=20)
    stats = {
        "events": count_table("events"),
        "detections": count_table("detections"),
        "incidents": count_table("incidents"),
        "by_severity": count_incidents_by_severity(),
        "active_blocks": len(list_blocklist(active_only=True)),
        "events_per_minute": get_events_per_minute_last_30(),
        "events_by_type": get_events_by_type_counts(),
        "detections_by_rule": get_detection_counts_by_rule(),
        "top_ips": get_top_source_ips(limit=5),
    }
    return render_template("index.html", events=events, incidents=incidents, stats=stats)


@app.route("/incident/<int:incident_id>")
def incident_detail(incident_id):
    incident = get_incident(incident_id)
    if incident is None:
        abort(404)
    events = get_events_by_ids(incident.get("event_ids", []))
    ai = get_ai_report(incident_id)
    blocked = is_blocked(incident.get("source_ip", ""))
    return render_template("incident.html", incident=incident, events=events, ai=ai, is_blocked=blocked)


@app.route("/event/<int:event_id>")
def event_detail(event_id):
    ev_list = get_events_by_ids([event_id])
    if not ev_list:
        abort(404)
    event = ev_list[0]
    blocked = is_blocked(event.get("source_ip", ""))
    return render_template("event.html", event=event, is_blocked=blocked)


@app.route("/countermeasures")
def countermeasures():
    auto_block = get_setting("auto_block", "off")
    blocks = list_blocklist(active_only=False)
    deceptive_events = get_recent_deceptive_events(limit=8)
    error = request.args.get("error")
    msg = request.args.get("msg")
    return render_template(
        "countermeasures.html",
        auto_block=auto_block,
        blocks=blocks,
        deceptive_events=deceptive_events,
        error=error,
        msg=msg,
    )


@app.route("/countermeasures/toggle", methods=["POST"])
def toggle_auto_block():
    current = get_setting("auto_block", "off")
    new_val = "off" if current.lower() == "on" else "on"
    set_setting("auto_block", new_val)
    return redirect(url_for("countermeasures", msg=f"Auto-block turned {new_val.upper()}"))


@app.route("/block", methods=["POST"])
def block_route():
    ip = request.form.get("ip", "").strip()
    reason = request.form.get("reason", "").strip() or "Manual block from dashboard"
    ref = request.form.get("return_to") or request.referrer or url_for("countermeasures")
    try:
        block_ip(ip, reason, block_type="manual")
    except ValueError as exc:
        if "countermeasures" in ref:
            return redirect(url_for("countermeasures", error=str(exc)))
        return redirect(ref)
    return redirect(ref)


@app.route("/unblock", methods=["POST"])
def unblock_route():
    ip = request.form.get("ip", "").strip()
    ref = request.form.get("return_to") or request.referrer or url_for("countermeasures")
    try:
        unblock_ip(ip)
    except ValueError:
        pass
    return redirect(ref)


@app.route("/unblock-all", methods=["POST"])
def unblock_all_route():
    active_entries = list_blocklist(active_only=True)
    for entry in active_entries:
        try:
            unblock_ip(entry["ip"])
        except ValueError:
            pass
    return redirect(url_for("countermeasures"))



@app.route("/incident/<int:incident_id>/analyze", methods=["POST"])
def analyze_incident(incident_id):
    if get_incident(incident_id) is None:
        abort(404)
    generate_report(incident_id)
    return redirect(url_for("incident_detail", incident_id=incident_id))


@app.route("/api/events")
def api_events():
    return jsonify(get_recent_events(limit=50))


@app.route("/api/stats")
def api_stats():
    """Return JSON with dashboard statistics.
    Structure:
    {
        "events_per_minute": [["2023-01-01T12:00Z", 5], ...],
        "events_by_type": {"login": 10, "scan": 5},
        "incidents_by_severity": {"low": 2, "medium": 1, "high": 0},
        "top_source_ips": [["1.2.3.4", 12], ...],
        "detections_by_rule": {"R001": 3, "R002": 1}
    }
    """
    return jsonify({
        "events_per_minute": get_events_per_minute_last_30(),
        "events_by_type": get_events_by_type_counts(),
        "incidents_by_severity": get_incidents_by_severity_counts(),
        "top_source_ips": get_top_source_ips(),
        "detections_by_rule": get_detection_counts_by_rule(),
    })

@app.route("/api/incidents")
def api_incidents():
    return jsonify(get_incidents(limit=20))


# Helper to read worker heartbeat
def get_worker_heartbeat():
    """Return ISO timestamp string of last heartbeat or None."""
    import os, datetime
    hb_path = os.path.join(os.path.dirname(__file__), 'data', 'worker_heartbeat')
    if not os.path.exists(hb_path):
        return None
    with open(hb_path, 'r', encoding='utf-8') as f:
        return f.read().strip()

# Route: clear history
@app.route("/clear-history", methods=["POST"])
def clear_history_route():
    """Delete all event/detection/incident data."""
    from database.db import clear_history
    clear_history()
    try:
        import worker
        worker._last_event_id = 0
    except Exception:
        pass
    if request.is_json or request.headers.get("Accept") == "application/json":
        return jsonify({"status": "cleared"})
    ref = request.referrer or url_for("index")
    return redirect(ref)

@app.route("/history")
def history():
    """Render the event history page with filters, pagination, and enriched info.
    Query params:
        page (int, default 1)
        service, source_ip, event_type, severity (exact match)
        q (text search over source_ip, event_type, metadata JSON string)
    """
    # --- extract filters ---
    page = int(request.args.get('page', 1))
    per_page = 50
    filters = {
        'service': request.args.get('service'),
        'source_ip': request.args.get('source_ip'),
        'event_type': request.args.get('event_type'),
        'severity': request.args.get('severity'),
        'q': request.args.get('q'),
    }
    # Build WHERE clause and parameters
    where_clauses = []
    params = []
    if filters['service']:
        where_clauses.append('service = ?')
        params.append(filters['service'])
    if filters['source_ip']:
        where_clauses.append('source_ip = ?')
        params.append(filters['source_ip'])
    if filters['event_type']:
        where_clauses.append('event_type = ?')
        params.append(filters['event_type'])
    if filters['severity']:
        where_clauses.append('severity = ?')
        params.append(filters['severity'])
    if filters['q']:
        # Simple LIKE search on several text columns + metadata_json
        q_like = f"%{filters['q']}%"
        where_clauses.append('(source_ip LIKE ? OR event_type LIKE ? OR metadata_json LIKE ?)')
        params.extend([q_like, q_like, q_like])
    where_sql = (' WHERE ' + ' AND '.join(where_clauses)) if where_clauses else ''
    # Count total rows for pagination
    from database.db import get_connection
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(f"SELECT COUNT(*) FROM events{where_sql}", params)
    total = cur.fetchone()[0]
    offset = (page - 1) * per_page
    # Fetch page rows (newest first)
    cur.execute(
        f"SELECT * FROM events{where_sql} ORDER BY id DESC LIMIT ? OFFSET ?",
        params + [per_page, offset]
    )
    rows = cur.fetchall()
    # Enrich each row
    from analyst.enrich import enrich
    from database.db import (
        get_incident_id_for_event,
        get_detections_for_event,
    )
    enriched = []
    for r in rows:
        ev = dict(r)
        # format id like EVT-000025
        ev['fmt_id'] = f"EVT-{ev['id']:06d}"
        # category / technique / outcome
        cat, technique, outcome = enrich(ev)
        ev['category'] = cat
        ev['technique'] = technique
        ev['outcome'] = outcome
        # rule hits (detections) for this event
        ev['rule_hits'] = ', '.join(d['rule_id'] for d in get_detections_for_event(ev['id']))
        # incident link (if any)
        inc_id = get_incident_id_for_event(ev['id'])
        ev['incident_id'] = inc_id
        enriched.append(ev)
    conn.close()
    # Build pagination info
    total_pages = (total + per_page - 1) // per_page
    return render_template(
        'history.html',
        events=enriched,
        page=page,
        total_pages=total_pages,
        filters=filters,
    )

def get_threat_level():
    """Return 'NORMAL', 'ELEVATED', or 'HIGH' based on current incidents.
    - NORMAL: no open incidents.
    - ELEVATED: highest open incident severity is 'medium'.
    - HIGH: any open incident with severity 'high'.
    Open incident: incidents where end_time is null or in future.
    """
    # Simple approach: fetch recent incidents and evaluate severity
    incidents = get_incidents(limit=100)  # fetch many
    max_sev = None
    for inc in incidents:
        if inc.get('end_time') is None or inc.get('end_time') == '':
            sev = inc.get('severity')
            if sev == 'high':
                return 'HIGH'
            if sev == 'medium' and max_sev != 'high':
                max_sev = 'medium'
    return 'ELEVATED' if max_sev == 'medium' else 'NORMAL'


@app.route("/analyze-events", methods=["POST"])
def analyze_events_route():
    # Supports JSON payload, form checkbox list, or comma-separated string
    ids = []
    if request.is_json:
        data = request.get_json(silent=True) or {}
        raw = data.get("event_ids", [])
        if isinstance(raw, list):
            ids = raw
        elif isinstance(raw, (int, str)):
            ids = [raw]
    else:
        # Form submission: request.form.getlist("event_ids")
        raw = request.form.getlist("event_ids")
        if not raw and "event_ids" in request.form:
            raw = request.form.get("event_ids", "").split(",")
        ids = raw

    parsed_ids = []
    for item in ids:
        try:
            val = int(str(item).strip())
            parsed_ids.append(val)
        except (ValueError, TypeError):
            continue

    if not parsed_ids:
        if request.is_json:
            return jsonify({"error": "No event IDs provided"}), 400
        return ("No event IDs provided", 400)

    if len(parsed_ids) > 100:
        if request.is_json:
            return jsonify({"error": "Selection exceeds maximum limit of 100 events"}), 400
        return ("Selection exceeds maximum limit of 100 events", 400)

    try:
        analysis_id, report = analyze_events(parsed_ids)
    except Exception as exc:
        if request.is_json:
            return jsonify({"error": str(exc)}), 500
        return (f"Analysis failed: {exc}", 500)

    if request.is_json:
        return jsonify({"id": analysis_id, "status": "ok", "report": report}), 200

    return redirect(url_for("analysis_detail", analysis_id=analysis_id))


@app.route("/analyses")
def analyses_list():
    items = list_analyses(limit=50)
    return render_template("analyses.html", analyses=items)


@app.route("/analysis/<int:analysis_id>")
def analysis_detail(analysis_id):
    analysis = get_analysis(analysis_id)
    if not analysis:
        abort(404)
    events = get_events_by_ids(analysis.get("event_ids", []))
    return render_template("analysis.html", analysis=analysis, events=events)


if __name__ == "__main__":
    initialize_database()
    app.run(host=config.DASHBOARD_HOST, port=config.DASHBOARD_PORT)
