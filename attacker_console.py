"""
attacker_console.py – Attacker Console (lab only).

Allows launching simulated attacker traffic scenarios against honeypot decoys.
Scenarios:
- T1: Normal connection
- T2: Brute force login
- T3: Light web browsing
- T4: Full attack chain
- T5: Slow login failures
"""

import sys
import os
import ipaddress
import threading
import queue
import subprocess
import datetime
import config

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, scrolledtext
    TKINTER_AVAILABLE = True
except ImportError:
    tk = None
    TKINTER_AVAILABLE = False

PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))

LAB_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("10.0.0.0/8"),
]


def get_python_executable():
    """Return virtualenv python executable if available, else sys.executable."""
    venv_py = os.path.join(PROJECT_ROOT, ".venv", "bin", "python")
    if os.path.isfile(venv_py) and os.access(venv_py, os.X_OK):
        return venv_py
    return sys.executable


def validate_target_address(ip_str: str) -> bool:
    """Validate that the target IP belongs strictly to allowed lab networks.
    Allowed: 127.0.0.0/8, 192.168.0.0/16, 10.0.0.0/8.
    """
    if not ip_str or not isinstance(ip_str, str):
        return False
    try:
        addr = ipaddress.ip_address(ip_str.strip())
        return any(addr in net for net in LAB_NETWORKS)
    except Exception:
        return False


SCENARIOS = [
    (
        "T1",
        "T1 Normal connection",
        "Connects to TCP decoy (port 2222) and disconnects immediately without sending credentials.",
    ),
    (
        "T2",
        "T2 Brute force login",
        "Sends 5 consecutive failed SSH logins in rapid succession.",
    ),
    (
        "T3",
        "T3 Light web browsing",
        "Sends HTTP requests to /, /admin, /wp-login.php, /nothing.",
    ),
    (
        "T4",
        "T4 Full attack chain",
        "Sends 5 failed logins, then probes web paths including sensitive /decoy-config.",
    ),
    (
        "T5",
        "T5 Slow login failures",
        "Sends 5 failed logins with 16s pauses between attempts (exceeds 60s sliding window).",
    ),
    (
        "T6",
        "T6 Reconnaissance probe",
        "Sends repeated requests to test deceptive server banners.",
    ),
]


class AttackerConsoleApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Attacker Console (lab only)")
        self.root.geometry("860x700")
        self.root.minsize(720, 560)

        self.current_proc = None
        self.active_scenario = None
        self.log_queue = queue.Queue()
        self.scenario_buttons = []
        self.tab_frames = {}
        self.log_texts = {}

        self._build_ui()

        # Handle window close cleanly
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Start periodic GUI queue poller
        self.root.after(100, self._poll_log_queue)

    def _build_ui(self):
        # Header
        header_frame = tk.Frame(self.root, bg="#34495e", padx=12, pady=10)
        header_frame.pack(fill=tk.X)

        title_lbl = tk.Label(
            header_frame,
            text="Attacker Console (lab only)",
            font=("Helvetica", 16, "bold"),
            fg="white",
            bg="#34495e",
        )
        title_lbl.pack(side=tk.LEFT)

        # Target IP Configuration Bar
        target_frame = tk.Frame(self.root, padx=12, pady=8, bg="#ecf0f1")
        target_frame.pack(fill=tk.X)

        target_lbl = tk.Label(
            target_frame,
            text="Target Address (Lab Only):",
            font=("Helvetica", 10, "bold"),
            bg="#ecf0f1",
        )
        target_lbl.pack(side=tk.LEFT, padx=(0, 6))

        default_target = getattr(config, "DECOY_BIND_HOST", "127.0.0.1")
        self.target_var = tk.StringVar(value=default_target)
        self.target_entry = tk.Entry(
            target_frame,
            textvariable=self.target_var,
            font=("Courier", 10, "bold"),
            width=18,
        )
        self.target_entry.pack(side=tk.LEFT, padx=(0, 10))

        range_lbl = tk.Label(
            target_frame,
            text="Allowed: 127.0.0.0/8, 192.168.0.0/16, 10.0.0.0/8",
            font=("Helvetica", 8, "italic"),
            fg="#7f8c8d",
            bg="#ecf0f1",
        )
        range_lbl.pack(side=tk.LEFT)

        self.stop_btn = tk.Button(
            target_frame,
            text="Stop Scenario",
            font=("Helvetica", 9, "bold"),
            bg="#c0392b",
            fg="white",
            padx=10,
            pady=2,
            state=tk.DISABLED,
            command=self.stop_scenario,
        )
        self.stop_btn.pack(side=tk.RIGHT)

        # Scenarios List Box
        scenarios_box = tk.LabelFrame(
            self.root,
            text=" Attack Scenarios ",
            font=("Helvetica", 11, "bold"),
            padx=10,
            pady=8,
        )
        scenarios_box.pack(fill=tk.X, padx=12, pady=6)

        for scen_id, title, desc in SCENARIOS:
            row = tk.Frame(scenarios_box, pady=4)
            row.pack(fill=tk.X)

            btn = tk.Button(
                row,
                text=f"Run {scen_id}",
                font=("Helvetica", 9, "bold"),
                bg="#2980b9",
                fg="white",
                width=9,
                command=lambda s=scen_id: self.run_scenario(s),
            )
            btn.pack(side=tk.LEFT, padx=(0, 10))
            self.scenario_buttons.append(btn)

            info_frame = tk.Frame(row)
            info_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)

            t_lbl = tk.Label(
                info_frame,
                text=title,
                font=("Helvetica", 9, "bold"),
                anchor="w",
            )
            t_lbl.pack(anchor="w")

            d_lbl = tk.Label(
                info_frame,
                text=desc,
                font=("Helvetica", 8),
                fg="#555555",
                anchor="w",
            )
            d_lbl.pack(anchor="w")

        # Output notebook
        output_box = tk.LabelFrame(
            self.root,
            text=" Console Output ",
            font=("Helvetica", 11, "bold"),
            padx=8,
            pady=8,
        )
        output_box.pack(fill=tk.BOTH, expand=True, padx=12, pady=6)

        self.notebook = ttk.Notebook(output_box)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        tab_defs = [
            ("all", "All Output"),
            ("T1", "T1 Normal"),
            ("T2", "T2 Brute Force"),
            ("T3", "T3 Light Web"),
            ("T4", "T4 Attack Chain"),
            ("T5", "T5 Slow Logins"),
            ("T6", "T6 Recon"),
        ]

        for tab_id, tab_label in tab_defs:
            tab_frame = tk.Frame(self.notebook)
            self.notebook.add(tab_frame, text=f" {tab_label} ")
            self.tab_frames[tab_id] = tab_frame

            st = scrolledtext.ScrolledText(
                tab_frame,
                wrap=tk.WORD,
                font=("Courier", 9),
                bg="#1e1e1e",
                fg="#00ff66",
                insertbackground="white",
            )
            st.pack(fill=tk.BOTH, expand=True)
            self.log_texts[tab_id] = st

        self.log_text = self.log_texts["all"]

    def _append_log(self, line):
        now_str = datetime.datetime.now().strftime("%H:%M:%S")
        entry = f"[{now_str}] {line}\n"

        # Always write to All Output
        all_widget = self.log_texts.get("all")
        if all_widget:
            all_widget.insert(tk.END, entry)
            all_widget.see(tk.END)

        # Write to active scenario tab if running
        if self.active_scenario and self.active_scenario in self.log_texts:
            scen_widget = self.log_texts[self.active_scenario]
            scen_widget.insert(tk.END, entry)
            scen_widget.see(tk.END)

    def _reader_thread(self, proc):
        try:
            for line in iter(proc.stdout.readline, ''):
                if not line:
                    break
                clean_line = line.rstrip('\r\n')
                if clean_line:
                    self.log_queue.put(clean_line)
        except (ValueError, OSError):
            pass
        finally:
            try:
                proc.stdout.close()
            except Exception:
                pass
            rc = proc.wait()
            self.log_queue.put(f"[process exited with code {rc}]")
            self.log_queue.put("__SCENARIO_FINISHED__")

    def _poll_log_queue(self):
        while not self.log_queue.empty():
            try:
                item = self.log_queue.get_nowait()
                if item == "__SCENARIO_FINISHED__":
                    self._on_scenario_done()
                else:
                    self._append_log(item)
            except queue.Empty:
                break
        self.root.after(100, self._poll_log_queue)

    def _on_scenario_done(self):
        self.current_proc = None
        for btn in self.scenario_buttons:
            btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)

    def run_scenario(self, scenario_id):
        target_ip = self.target_var.get().strip()
        if not validate_target_address(target_ip):
            msg = f"Address '{target_ip}' rejected. Only lab addresses (127.0.0.0/8, 192.168.0.0/16, 10.0.0.0/8) are permitted."
            self._append_log(f"[error] {msg}")
            if messagebox:
                messagebox.showerror("Invalid Target", msg)
            return

        for btn in self.scenario_buttons:
            btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)

        self.active_scenario = scenario_id
        if scenario_id in self.tab_frames and hasattr(self, "notebook"):
            try:
                self.notebook.select(self.tab_frames[scenario_id])
            except Exception:
                pass

        py_exe = get_python_executable()
        cmd = [py_exe, "scripts/simulate_events.py", scenario_id, target_ip]
        self._append_log(f"[console] Launching scenario {scenario_id} against {target_ip}...")

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
            self.current_proc = proc
            t = threading.Thread(target=self._reader_thread, args=(proc,), daemon=True)
            t.start()
        except Exception as e:
            self._append_log(f"[error] Failed to start simulation: {e}")
            self._on_scenario_done()

    def stop_scenario(self):
        if self.current_proc and self.current_proc.poll() is None:
            self._append_log("[console] Stopping running scenario...")
            try:
                self.current_proc.terminate()
            except OSError:
                pass
            # Force kill if still running after brief moment
            def _kill_if_alive(p):
                try:
                    p.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    try:
                        p.kill()
                    except OSError:
                        pass
            threading.Thread(target=_kill_if_alive, args=(self.current_proc,), daemon=True).start()

    def on_closing(self):
        self.stop_scenario()
        self.root.destroy()


def main():
    if not TKINTER_AVAILABLE:
        print("Tkinter is not available on this system.")
        print("On Arch Linux: sudo pacman -S tk")
        print("On Debian/Ubuntu: sudo apt install python3-tk")
        print("For headless environments, run scripts directly:")
        print("  python scripts/simulate_events.py <SCENARIO> [host]")
        sys.exit(1)

    root = tk.Tk()
    app = AttackerConsoleApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()

