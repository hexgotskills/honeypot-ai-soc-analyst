CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL,
  source_ip TEXT NOT NULL,
  service TEXT NOT NULL,
  event_type TEXT NOT NULL,
  outcome TEXT,
  metadata_json TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS detections (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  unique_key TEXT NOT NULL UNIQUE,
  rule_id TEXT NOT NULL,
  rule_name TEXT NOT NULL,
  source_ip TEXT NOT NULL,
  event_ids TEXT NOT NULL,
  match_count INTEGER NOT NULL,
  window_seconds INTEGER NOT NULL,
  reason TEXT NOT NULL,
  severity TEXT NOT NULL,
  detected_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS incidents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source_ip TEXT NOT NULL,
  start_time TEXT NOT NULL,
  end_time TEXT NOT NULL,
  severity TEXT NOT NULL,
  rule_ids TEXT,
  status TEXT NOT NULL DEFAULT 'open',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS incident_events (
  incident_id INTEGER NOT NULL,
  event_id INTEGER NOT NULL,
  PRIMARY KEY (incident_id, event_id)
);
CREATE TABLE IF NOT EXISTS ai_reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'not_configured',
  report_json TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- New blocklist table for manual and automatic IP blocks
CREATE TABLE IF NOT EXISTS blocklist (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT NOT NULL UNIQUE,
  reason TEXT NOT NULL,
  block_type TEXT NOT NULL CHECK(block_type IN ('manual','auto')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  active INTEGER NOT NULL DEFAULT 1,
  unblocked_at TEXT
);

-- Settings table for feature flags (key/value as TEXT)
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- Multi-event analyses table
CREATE TABLE IF NOT EXISTS analyses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  event_ids TEXT NOT NULL,
  provider TEXT NOT NULL,
  report_json TEXT NOT NULL
);
