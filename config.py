import os

# Database file path – can be overridden via DATABASE_PATH env var.
# If a relative path is given, resolve it relative to this config file.
_DB_PATH = os.getenv('DATABASE_PATH', 'data/soc.db')
if not os.path.isabs(_DB_PATH):
    DATABASE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), _DB_PATH))
else:
    DATABASE_PATH = _DB_PATH
# Host/IP on which decoy services bind (loopback for lab use)
SUSPICIOUS_PATHS = ["/admin", "/decoy-config", "/wp-login.php", "/.env", "/phpmyadmin"]
AUTH_FAIL_COUNT = 5
AUTH_WINDOW = 60
WEB_RATE_COUNT = 20
WEB_RATE_WINDOW = 30
PROBE_COUNT = 3
COMBO_WINDOW = 300
CORRELATION_WINDOW = 300
DECOY_BIND_HOST = os.getenv("DECOY_BIND_HOST", "127.0.0.1")

# TCP port for the SSH‑style login decoy
TCP_DECOY_PORT = 2222

# HTTP port for the web decoy (not used yet)
HTTP_DECOY_PORT = 8080

# Dashboard settings (placeholder)
DASHBOARD_HOST = os.getenv("DASHBOARD_HOST", "127.0.0.1")
DASHBOARD_PORT = 5000

# AI analyst configuration (set AI_PROVIDER=gemini and AI_API_KEY in .env)
AI_PROVIDER = os.getenv("AI_PROVIDER", "mock")
AI_API_KEY = os.getenv("AI_API_KEY", "")
AI_MODEL = os.getenv("AI_MODEL", "gemini-2.5-flash-lite")
