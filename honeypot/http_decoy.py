# Run with: python -m honeypot.http_decoy or python honeypot/http_decoy.py
import sys, os
import random
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from flask import Flask, request, Response
import config
from honeypot.event_logger import log_event
from database.db import initialize_database, is_blocked

# Countermeasure: Server Banner Obfuscation & Dynamic OS Fingerprint Morphing
SERVER_BANNERS = [
    "Apache/2.4.52 (Ubuntu)",
    "nginx/1.18.0 (Ubuntu)",
    "Microsoft-IIS/10.0",
    "lighttpd/1.4.65",
]

app = Flask(__name__)

@app.before_request
def block_check():
    # Application-level block check (not a firewall rule).
    if is_blocked(request.remote_addr):
        request._blocked = True
        # Log one event of type blocked_attempt and do nothing else
        log_event(
            request.remote_addr,
            "http_decoy",
            "blocked_attempt",
            "blocked",
            {"service": "http_decoy", "port": config.HTTP_DECOY_PORT},
        )
        print(f"[http_decoy] blocked request {request.method} {request.path} from {request.remote_addr}", flush=True)
        return Response("Blocked\n", status=403, mimetype="text/plain")

app.config["MAX_CONTENT_LENGTH"] = 10000

@app.route('/')
def index():
    return "<h1>Welcome</h1>"

@app.route('/login', methods=['GET', 'POST'])
def login():
    return "Invalid username or password"

@app.route('/admin')
def admin():
    return "Access denied"

@app.route('/robots.txt')
def robots():
    return Response("Disallow: /admin", mimetype='text/plain')

@app.route('/decoy-config')
def decoy_config():
    return "config not available"

@app.errorhandler(404)
def not_found(e):
    return "Not found", 404

@app.after_request
def after(resp):
    # Dynamically morph the Server response header to deceive reconnaissance scanners
    server_banner = random.choice(SERVER_BANNERS)
    resp.headers["Server"] = server_banner
    if getattr(request, '_blocked', False):
        return resp
    path = request.path
    event_type = "decoy_resource_access" if path == "/decoy-config" else "http_request"
    suspicious = path in config.SUSPICIOUS_PATHS or resp.status_code == 404
    metadata = {
        "method": request.method,
        "path": path[:100],
        "status": resp.status_code,
        "suspicious": suspicious,
        "server_banner": server_banner,
    }
    log_event(request.remote_addr, "http_decoy", event_type, str(resp.status_code), metadata)
    print(f"[http_decoy] {request.method} {path} from {request.remote_addr} (Server: {server_banner})", flush=True)
    return resp

if __name__ == "__main__":
    initialize_database()
    print(f"[http_decoy] listening on {config.DECOY_BIND_HOST}:{config.HTTP_DECOY_PORT}", flush=True)
    app.run(host=config.DECOY_BIND_HOST, port=config.HTTP_DECOY_PORT)
