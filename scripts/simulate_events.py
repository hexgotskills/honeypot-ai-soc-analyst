import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import time, socket, requests, config

def _allowed(host):
    # allow loopback or private IPs only
    try:
        ip = socket.inet_aton(host)
    except Exception:
        print('only lab addresses allowed')
        sys.exit(1)
    parts = host.split('.')
    if host.startswith('127.') or host.startswith('10.') or host.startswith('192.168.'):
        return True
    if host.startswith('172.') and 16 <= int(parts[1]) <= 31:
        return True
    print('only lab addresses allowed')
    sys.exit(1)

def failed_logins(host, n, pause=0):
    for i in range(n):
        print(f"[simulate] sending login attempt {i+1}/{n} to {host}:{config.TCP_DECOY_PORT}", flush=True)
        s = socket.socket()
        try:
            s.connect((host, config.TCP_DECOY_PORT))
        except (ConnectionRefusedError, socket.error, OSError) as e:
            print(f"[simulate] Error: Connection refused on {host}:{config.TCP_DECOY_PORT}.", flush=True)
            print(f"[simulate] Hint: The TCP decoy is not running. Click 'Start all' in the Control Panel first.", flush=True)
            sys.exit(1)
        try:
            s.sendall(b'fakeuser\n')
            time.sleep(0.2)
            s.sendall(b'fakepass123\n')
            time.sleep(0.2)
        except (ConnectionResetError, BrokenPipeError, socket.error) as e:
            print(f"[simulate] Connection closed/reset by honeypot (IP {host} is blocked by SOC countermeasures!).", flush=True)
            print(f"[simulate] Tip: Unblock {host} on the Countermeasures tab at http://127.0.0.1:5000/countermeasures", flush=True)
            return
        finally:
            try:
                s.close()
            except Exception:
                pass
        if pause > 0 and i < n - 1:
            print(f"[simulate] pausing for {pause}s...", flush=True)
            time.sleep(pause)

def web_requests(host, paths):
    for p in paths:
        url = f"http://{host}:{config.HTTP_DECOY_PORT}{p}"
        print(f"[simulate] requesting {p} from {url}", flush=True)
        try:
            r = requests.get(url, timeout=5)
            print(f"[simulate] got status {r.status_code} for {p}", flush=True)
        except requests.exceptions.ConnectionError:
            print(f"[simulate] Error: Connection refused on {url}.", flush=True)
            print(f"[simulate] Hint: The HTTP decoy is not running. Click 'Start all' in the Control Panel first.", flush=True)
            sys.exit(1)
        except Exception as e:
            print(f"[simulate] request failed for {p}: {e}", flush=True)

def reconnaissance_probes(host, count=4):
    for i in range(count):
        url = f"http://{host}:{config.HTTP_DECOY_PORT}/"
        print(f"[simulate] sending reconnaissance probe {i+1}/{count} to {url}", flush=True)
        try:
            r = requests.get(url, timeout=5)
            print(f"HTTP/1.1 {r.status_code} {r.reason}", flush=True)
            for k, v in r.headers.items():
                print(f"{k}: {v}", flush=True)
            print("-" * 40, flush=True)
            time.sleep(0.4)
        except requests.exceptions.ConnectionError:
            print(f"[simulate] Error: Connection refused on {url}.", flush=True)
            print(f"[simulate] Hint: The HTTP decoy is not running. Click 'Start all' in the Control Panel first.", flush=True)
            sys.exit(1)
        except Exception as e:
            print(f"[simulate] probe failed: {e}", flush=True)

def run_scenario(name, host=None):
    host = host or config.DECOY_BIND_HOST
    _allowed(host)
    print(f"[simulate] starting scenario {name} targeting {host}", flush=True)
    if name == 'T1':
        print(f"[simulate] connecting to TCP decoy at {host}:{config.TCP_DECOY_PORT}", flush=True)
        s = socket.socket()
        try:
            s.connect((host, config.TCP_DECOY_PORT))
            s.close()
            print(f"[simulate] closed connection without authenticating", flush=True)
        except (ConnectionRefusedError, socket.error, OSError) as e:
            print(f"[simulate] Error: Connection refused on {host}:{config.TCP_DECOY_PORT}.", flush=True)
            print(f"[simulate] Hint: The TCP decoy is not running. Click 'Start all' in the Control Panel first.", flush=True)
            sys.exit(1)
    elif name == 'T2':
        failed_logins(host, 5)
    elif name == 'T3':
        web_requests(host, ['/', '/admin', '/wp-login.php', '/nothing'])
    elif name == 'T4':
        failed_logins(host, 5)
        web_requests(host, ['/admin', '/wp-login.php', '/decoy-config', '/'])
    elif name == 'T5':
        failed_logins(host, 5, pause=16)
    elif name == 'T6':
        reconnaissance_probes(host, 4)
    else:
        print(f"[simulate] unknown scenario: {name}", flush=True)
        sys.exit(1)
    print(f"[simulate] scenario {name} finished", flush=True)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python scripts/simulate_events.py SCENARIO [host]')
        sys.exit(1)
    run_scenario(sys.argv[1], sys.argv[2] if len(sys.argv)>2 else None)
