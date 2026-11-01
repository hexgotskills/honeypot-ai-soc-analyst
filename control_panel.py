"""
control_panel.py – Honeypot SOC Control Panel (Tkinter GUI).

Controls all components:
1. TCP decoy (port 2222)
2. HTTP decoy (port 8080)
3. Worker (background correlation loop)
4. Dashboard (Flask web UI, port 5000)
"""

import sys
import os
import time
import socket
import threading
import queue
import datetime
import subprocess
import webbrowser

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, scrolledtext
    TKINTER_AVAILABLE = True
except ImportError:
    tk = None
    TKINTER_AVAILABLE = False

import config

PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))

# Descriptions for the four SOC components
COMPONENT_INFO = {
    "tcp_decoy": {
        "title": "TCP Decoy",
        "port": config.TCP_DECOY_PORT,
        "description": f"TCP decoy: listens on port {config.TCP_DECOY_PORT} and pretends to be a login service.",
        "has_port": True,
    },
    "http_decoy": {
        "title": "HTTP Decoy",
        "port": config.HTTP_DECOY_PORT,
        "description": f"HTTP decoy: listens on port {config.HTTP_DECOY_PORT} trapping unauthorized web probes.",
        "has_port": True,
    },
    "worker": {
        "title": "Worker",
        "port": "-",
        "description": "Worker: background daemon analyzing events and correlating alerts into incidents.",
        "has_port": False,
    },
    "dashboard": {
        "title": "Dashboard",
        "port": config.DASHBOARD_PORT,
        "description": f"Dashboard: Flask web interface on port {config.DASHBOARD_PORT} presenting alerts and metrics.",
        "has_port": True,
    },
}


def get_python_executable():
    """Return virtualenv python executable if available, else sys.executable."""
    venv_py = os.path.join(PROJECT_ROOT, ".venv", "bin", "python")
    if os.path.isfile(venv_py) and os.access(venv_py, os.X_OK):
        return venv_py
    return sys.executable


def get_component_commands(python_exe=None):
    """Return command lists used to start each component."""
    if python_exe is None:
        python_exe = get_python_executable()
    return {
        "tcp_decoy": [python_exe, "-m", "honeypot.tcp_decoy"],
        "http_decoy": [python_exe, "-m", "honeypot.http_decoy"],
        "worker": [python_exe, "worker.py"],
        "dashboard": [python_exe, "app.py"],
    }


def is_port_listening(host, port, timeout=0.5):
    """Check if a TCP port is currently open and accepting connections."""
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def terminate_process(proc, timeout=3.0):
    """Terminate a process gracefully, then kill after timeout if still alive."""
    if proc is None or proc.poll() is not None:
        return
    try:
        proc.terminate()
    except OSError:
        pass
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except OSError:
            pass
        try:
            proc.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            pass


class ControlPanelApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Honeypot SOC Control Panel")
        self.root.geometry("860x700")
        self.root.minsize(720, 560)

        self.processes = {
            "tcp_decoy": None,
            "http_decoy": None,
            "worker": None,
            "dashboard": None,
        }
        self.verified_listening = set()
        self.log_queue = queue.Queue()
        self.status_labels = {}

        self._build_ui()

        # Handle window close cleanly
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Start periodic GUI pollers
        self.root.after(100, self._poll_log_queue)
        self.root.after(1000, self._check_statuses)

    def _build_ui(self):
        # Top banner
        header_frame = tk.Frame(self.root, bg="#2c3e50", padx=12, pady=10)
        header_frame.pack(fill=tk.X)

        title_lbl = tk.Label(
            header_frame,
            text="Honeypot SOC Control Panel",
            font=("Helvetica", 16, "bold"),
            fg="white",
            bg="#2c3e50",
        )
        title_lbl.pack(side=tk.LEFT)

        # Buttons bar
        btn_frame = tk.Frame(self.root, pady=10, padx=12)
        btn_frame.pack(fill=tk.X)

        self.start_btn = tk.Button(
            btn_frame,
            text="Start all",
            font=("Helvetica", 10, "bold"),
            bg="#27ae60",
            fg="white",
            padx=12,
            pady=4,
            command=self.start_all,
        )
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = tk.Button(
            btn_frame,
            text="Stop all",
            font=("Helvetica", 10, "bold"),
            bg="#c0392b",
            fg="white",
            padx=12,
            pady=4,
            command=self.stop_all,
        )
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        self.dash_btn = tk.Button(
            btn_frame,
            text="Open dashboard",
            font=("Helvetica", 10),
            bg="#2980b9",
            fg="white",
            padx=12,
            pady=4,
            command=self.open_dashboard,
        )
        self.dash_btn.pack(side=tk.LEFT, padx=5)

        # Status cards container
        status_box = tk.LabelFrame(
            self.root,
            text=" Component Status ",
            font=("Helvetica", 11, "bold"),
            padx=10,
            pady=8,
        )
        status_box.pack(fill=tk.X, padx=12, pady=4)

        for key, info in COMPONENT_INFO.items():
            row = tk.Frame(status_box, pady=4)
            row.pack(fill=tk.X)

            name_lbl = tk.Label(
                row,
                text=f"{info['title']} (Port {info['port']}):",
                font=("Helvetica", 10, "bold"),
                width=24,
                anchor="w",
            )
            name_lbl.pack(side=tk.LEFT)

            stat_lbl = tk.Label(
                row,
                text="Stopped",
                font=("Helvetica", 9, "bold"),
                fg="#7f8c8d",
                anchor="w",
            )
            stat_lbl.pack(side=tk.LEFT, fill=tk.X, expand=True)
            self.status_labels[key] = stat_lbl

            desc_lbl = tk.Label(
                row,
                text=info["description"],
                font=("Helvetica", 8),
                fg="#555555",
                wraplength=480,
                justify="left",
                anchor="w",
            )
            desc_lbl.pack(side=tk.RIGHT, padx=5)

        # Log output container
        log_frame = tk.LabelFrame(
            self.root,
            text=" Console Activity Logs ",
            font=("Helvetica", 11, "bold"),
            padx=8,
            pady=8,
        )
        log_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=8)

        # Tabbed console frames
        self.notebook = ttk.Notebook(log_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self.log_texts = {}
        tab_defs = [
            ("all", "All Logs"),
            ("tcp_decoy", "TCP Decoy"),
            ("http_decoy", "HTTP Decoy"),
            ("worker", "Worker"),
            ("dashboard", "Dashboard"),
        ]

        for tab_id, tab_label in tab_defs:
            tab_frame = tk.Frame(self.notebook)
            self.notebook.add(tab_frame, text=f" {tab_label} ")

            st = scrolledtext.ScrolledText(
                tab_frame,
                wrap=tk.WORD,
                font=("Courier", 9),
                bg="#ffffff",
                fg="#222222",
            )
            st.pack(fill=tk.BOTH, expand=True)

            # Background color per component tag
            st.tag_config("tcp_decoy", background="#e8f4f8", foreground="#003366")
            st.tag_config("http_decoy", background="#fef9e7", foreground="#7d5a00")
            st.tag_config("worker", background="#f4ecf7", foreground="#4a154b")
            st.tag_config("dashboard", background="#eafaf1", foreground="#1e8449")
            st.tag_config("system", background="#f2f3f4", foreground="#333333")

            self.log_texts[tab_id] = st

        self.log_text = self.log_texts["all"]

    def _append_log(self, component, line):
        now_str = datetime.datetime.now().strftime("%H:%M:%S")
        entry_all = f"[{now_str}] [{component}] {line}\n"
        entry_comp = f"[{now_str}] {line}\n"

        # Always append to 'all' tab
        all_widget = self.log_texts.get("all")
        if all_widget:
            all_widget.insert(tk.END, entry_all, component)
            all_widget.see(tk.END)

        # Append to dedicated component tab if available
        comp_widget = self.log_texts.get(component)
        if comp_widget:
            comp_widget.insert(tk.END, entry_comp, component)
            comp_widget.see(tk.END)

    def _reader_thread(self, proc, comp_name):
        try:
            for line in iter(proc.stdout.readline, ''):
                if not line:
                    break
                clean_line = line.rstrip('\r\n')
                if clean_line:
                    self.log_queue.put((comp_name, clean_line))
        except (ValueError, OSError):
            pass
        finally:
            try:
                proc.stdout.close()
            except Exception:
                pass

    def _poll_log_queue(self):
        while not self.log_queue.empty():
            try:
                comp_name, line = self.log_queue.get_nowait()
                self._append_log(comp_name, line)
            except queue.Empty:
                break
        self.root.after(100, self._poll_log_queue)

    def _check_statuses(self):
        for key, proc in self.processes.items():
            info = COMPONENT_INFO[key]
            lbl = self.status_labels.get(key)
            if not lbl:
                continue

            if proc is None or proc.poll() is not None:
                self.verified_listening.discard(key)
                lbl.config(text="Stopped", fg="#7f8c8d")
            else:
                if info["has_port"]:
                    if key in self.verified_listening or is_port_listening(config.DECOY_BIND_HOST, info["port"]):
                        self.verified_listening.add(key)
                        lbl.config(
                            text=f"{info['title']} currently listening on port {info['port']}",
                            fg="#27ae60",
                        )
                    else:
                        lbl.config(text="Starting (waiting for port)...", fg="#d35400")
                else:
                    lbl.config(text=f"{info['title']} running", fg="#27ae60")

        self.root.after(1000, self._check_statuses)

    def start_all(self):
        commands = get_component_commands()
        self.verified_listening.clear()
        for key, cmd in commands.items():
            current_proc = self.processes.get(key)
            if current_proc is not None and current_proc.poll() is None:
                self._append_log("system", f"{key} is already running.")
                continue

            info = COMPONENT_INFO[key]
            if info["has_port"] and is_port_listening(config.DECOY_BIND_HOST, info["port"]):
                self._append_log("system", f"WARNING: Port {info['port']} ({key}) is already in use by Docker or an external process!")
                self._append_log("system", f"Stop Docker with 'docker compose down' to use local desktop mode.")
                continue

            try:
                env = os.environ.copy()
                env["PYTHONUNBUFFERED"] = "1"
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    cwd=PROJECT_ROOT,
                    env=env,
                )
                self.processes[key] = proc
                t = threading.Thread(
                    target=self._reader_thread,
                    args=(proc, key),
                    daemon=True,
                )
                t.start()
                self._append_log("system", f"Started {key} (PID {proc.pid})")
            except Exception as e:
                self._append_log("system", f"Failed to start {key}: {e}")

        self._check_statuses()

    def stop_all(self):
        self._append_log("system", "Stopping all components...")
        self.verified_listening.clear()
        for key, proc in self.processes.items():
            if proc is not None and proc.poll() is None:
                terminate_process(proc, timeout=3.0)
                self.processes[key] = None
                self._append_log("system", f"Stopped {key}")
            else:
                self.processes[key] = None

        self._check_statuses()

    def open_dashboard(self):
        url = f"http://{config.DASHBOARD_HOST}:{config.DASHBOARD_PORT}"
        self._append_log("system", f"Opening browser to {url}")
        webbrowser.open(url)

    def on_closing(self):
        self.stop_all()
        self.root.destroy()


def main():
    if not TKINTER_AVAILABLE:
        print("Tkinter is not available on this system.")
        print("On Arch Linux: sudo pacman -S tk")
        print("On Debian/Ubuntu: sudo apt install python3-tk")
        print("For headless environments, use bash start_all.sh instead.")
        sys.exit(1)

    root = tk.Tk()
    app = ControlPanelApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()

