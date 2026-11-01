# Honeypot AI SOC

A tiny lab‑only security system with two fake services, a SQLite logger, rule‑based detection, incident correlation and optional Gemini AI reporting.

**Pipeline:** decoy → event logger → detection → correlation → (optional) AI analyst.

**Folder layout:**
```
app.py  worker.py  config.py  requirements.txt
honeypot/   detection/   database/   analyst/
templates/  static/     scripts/    tests/   data/
```

**Run:**
```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # set AI_PROVIDER, AI_API_KEY if you want real Gemini
bash start_all.sh       # launches decoys, worker and dashboard (Ctrl+C stops)
```

**Run with Docker:**
```bash
# Build and start all 4 services (decoys, worker, and dashboard) in the background:
docker compose up --build -d

# View live container logs:
docker compose logs -f

# Stop all services:
docker compose down

# Stop and completely reset the SQLite database volume:
docker compose down -v
```

> **Note on GUI Tools:** The Tkinter GUI windows (`control_panel.py` and `attacker_console.py`) are not part of the container image. They run on the host machine and can interact with the Dockerized services via `127.0.0.1` (ports 2222, 8080, and 5000).
> If Docker is not installed on Arch Linux (or permission is denied on docker.sock):
> ```bash
> sudo pacman -S docker docker-compose
> sudo systemctl start docker
> sudo usermod -aG docker $USER
> newgrp docker
> ```

**Demo:**
1. Start the control panel: `python control_panel.py`
2. Click **Start all** to boot both honeypots, worker daemon, and dashboard.
3. Start the attacker console: `python attacker_console.py`
4. Run attack scenarios (T1–T5) and monitor the live log stream.
5. Click **Open dashboard** (or visit `http://127.0.0.1:5000`) to observe events, alerts, incidents, and AI analysis reports.

> **Note:** Tkinter requires a graphical desktop environment. On a headless VM or server, use `bash start_all.sh` and test via `python scripts/simulate_events.py <SCENARIO>`.
> If Tkinter is missing on Arch Linux, install it via: `sudo pacman -S tk`. On Debian/Ubuntu: `sudo apt install python3-tk`.

**Test:** `pytest -q` (all pass).

**Evaluate:** `python scripts/evaluate.py` – prompts before wiping the DB and prints a CSV report.

**Gemini:** put the free API key in `.env` (`AI_PROVIDER=gemini`). The key is never committed.

**Limits:**
- Rules use simple thresholds, not production‑grade signatures.
- One source IP is treated as a single actor.
- Test set is tiny; real traffic will differ.
- AI reports are explanations, not forensic proof.
- Intended for isolated lab use only.
