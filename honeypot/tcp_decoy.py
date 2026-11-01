# Simple TCP decoy that mimics an SSH login prompt.
# No external dependencies – only the Python standard library.

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import socket
import threading
from honeypot.event_logger import log_event
import config
from database.db import initialize_database, is_blocked
# Settings that can be tweaked easily.
MAX_BYTES = 256
TIMEOUT_SECONDS = 10
MAX_ATTEMPTS = 3

def handle_client(conn, addr):
    """Interact with a single client.
    It sends a fake login prompt, receives data, logs the attempt and
    always replies with "Login incorrect".
    """
    # Check blocklist before any interaction (application-level block only, not a firewall)
    if is_blocked(addr[0]):
        try:
            port = conn.getsockname()[1]
        except Exception:
            port = getattr(config, "TCP_DECOY_PORT", 2222)
        # Log one event of type blocked_attempt and do nothing else
        log_event(addr[0], "tcp_login_decoy", "blocked_attempt", "blocked", {"service": "tcp_login_decoy", "port": port})
        print(f"[tcp_decoy] blocked connection attempt from {addr[0]}:{addr[1]}", flush=True)
        conn.close()
        return

    try:
        conn.settimeout(TIMEOUT_SECONDS)
        # Log that a connection was accepted.
        log_event(addr[0], "tcp_login_decoy", "connection_opened", "accepted", {})
        print(f"[tcp_decoy] connection from {addr[0]}:{addr[1]}", flush=True)

        for _ in range(MAX_ATTEMPTS):
            # Ask for username.
            conn.sendall(b"login: ")
            try:
                user_data = conn.recv(MAX_BYTES)
                if not user_data:
                    break
            except socket.timeout:
                break
            # Ask for password.
            conn.sendall(b"password: ")
            try:
                pass_data = conn.recv(MAX_BYTES)
                if not pass_data:
                    break
            except socket.timeout:
                break
            # Record only the length of the received strings.
            username_len = len(user_data.strip())
            password_len = len(pass_data.strip())
            log_event(
                addr[0],
                "tcp_login_decoy",
                "login_attempt",
                "simulated_failure",
                {"username_length": username_len, "password_length": password_len},
            )
            print(f"[tcp_decoy] login attempt from {addr[0]}:{addr[1]} (length: {username_len})", flush=True)
            conn.sendall(b"Login incorrect\n")
    except (socket.error, OSError) as e:
        print(f"[tcp_decoy] connection error: {e}", flush=True)
    finally:
        conn.close()

def main():
    host = getattr(config, "DECOY_BIND_HOST", "127.0.0.1")
    port = getattr(config, "TCP_DECOY_PORT", 2222)
    initialize_database()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen()
    print(f"[tcp_decoy] listening on {host}:{port}", flush=True)
    try:
        while True:
            conn, addr = server.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            thread.start()
    except KeyboardInterrupt:
        print("[tcp_decoy] stopped", flush=True)
    finally:
        server.close()

if __name__ == "__main__":
    main()
