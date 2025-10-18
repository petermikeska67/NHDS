# Network Health & Device Scanner 

A lightweight command-line tool that discovers the devices on your local IPv4 network, checks their reachability, and presents the results in a readable table or JSON payload. Perfect for quickly answering _“Who’s on my Wi-Fi, and are they online?”_

## Features

- Auto-detects your local `/24` subnet (or target a custom CIDR).
- Concurrently pings hosts to determine reachability and latency.
- Filters out inactive addresses so you only see discovered devices.
- Resolves hostnames, fetches MAC addresses from ARP, and maps vendors via OUI prefixes (with automatic lookups against macvendorlookup.com when needed).
- Toggle remote vendor lookups on demand or force a fresh vendor refresh for accuracy.
- Renders a Rich-powered table with online/offline status indicators and highlights newly discovered devices.
- Maintains a rolling history (JSON) so you can spot new, returning, or missing devices between runs.
- Config-driven device aliases let you attach friendly names/tags to IP or MAC prefixes.
- Ships with a minimalist Flask web UI for ad-hoc scans, vendor controls, history insights, and per-host ping tests.
- Web UI settings drawer (gear icon) lets you tweak defaults without editing YAML.
- Optional live refresh mode for continuous monitoring.
- Export scan results directly to JSON or CSV for downstream automation.
- Webhook notifications (generic + Discord) fire on new/returning/missing devices.

## Requirements

- Python 3.9 or newer.
- `ping` and `arp` commands available on the system (macOS, Linux, and Windows are supported).
- `scapy` (installed via `pip`) is used for fast ARP discovery when available.
- Outbound HTTPS access to `macvendorlookup.com` (optional but recommended for vendor enrichment).
- Optional: elevated privileges improve ARP discovery accuracy on some systems.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows, use `.venv\Scripts\activate`
pip install -r requirements.txt
cp config/settings.example.yaml config/settings.yaml  # customise as needed
```

Set `NSHS_CONFIG_FILE=/path/to/settings.yaml` if you keep your configuration elsewhere.

## Configuration

Configuration is YAML-driven (`config/settings.yaml`). Key blocks:

- `network`: default CIDR, concurrency, ping/ARP timeouts, vendor lookup defaults, history storage path.
- `notifications`: enable/disable webhooks, target URL, optional shared secret, timeout.
- `notifications.discord_webhook_url`: optional direct Discord webhook for rich alerts.
- `web`: optional auth token placeholder. When `require_auth` is true, ensure your reverse proxy injects an `Authorization: Bearer <token>` header before requests reach the app (pair with TLS/edge authentication upstream).
- `devices`: map IP addresses or MAC prefixes to friendly names and tags for richer reporting.

Aliases support exact IP matches or MAC prefix wildcards (e.g. `AA:BB:CC*`).

## Usage

```bash
python main.py [options]
```

Common options:

- `--cidr 192.168.0.0/24` – scan a specific network instead of the auto-detected one.
- `--concurrency 128` – adjust concurrent probes (default: 64).
- `--timeout 1.5` – ping timeout per host in seconds.
- `--interval 30` – re-run the scan every _n_ seconds with a live-updating table.
- `--notify-changes` – print badges when devices appear, vanish, or come back online.
- `--json` – emit JSON instead of a table (no refresh).
- `--export-json result.json` / `--export-csv result.csv` – persist the latest scan.
- `--vendor-offline` – skip the macvendorlookup.com API (offline mode).
- `--vendor-refresh` – force a fresh vendor lookup even if cached locally.
- `--vendor-file path/to/custom.json` – supply your own MAC prefix map.
- `--history-file data/scan_history.json` – customise where history is stored (default shown).
- `--history-max 100` – cap the number of stored history entries.
- `--arp-timeout 3.0` – adjust ARP discovery timeout (seconds).

Example session:

```bash
python main.py --interval 30
```

Example output:

```
┏━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━┓
┃ IP           ┃ Hostname    ┃ MAC              ┃ Vendor         ┃ Latency┃ Status   ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━┩
│ 192.168.1.1  │ Router      │ 40:B0:76:12:34:56│ TP-Link        │ 2.0 ms │ 🟢 Online │
│ 192.168.1.42 │ Desktop-PC  │ D4:6D:6D:98:76:54│ Apple          │ 15.4 ms│ 🟢 Online │
│ 192.168.1.99 │ —           │ —                │ Unknown        │ —      │ 🔴 Offline│
└──────────────┴─────────────┴──────────────────┴────────────────┴────────┴──────────┘
Hosts scanned: 254 • Online: 2 • Duration: 3.12s • Started: 2024-05-27T18:13:42.123456Z
```

## Web Interface

Fire up the Flask app to run scans from your browser, re-test individual hosts, and download the latest results as JSON/CSV.

```bash
export FLASK_APP=web.app
flask run
# or: python -m flask --app web.app run
```

Then visit `http://127.0.0.1:5000/` to:

- Launch full-network scans with custom concurrency, timeouts, ARP settings, and vendor lookup controls.
- Persist default settings, history limits, and webhook endpoints directly from the UI (toggle the ⚙️ drawer).
- Run on-demand ping tests for any discovered device.
- Download the latest scan in JSON or CSV, or pull the cumulative history as JSON.
- Review quick change notes (new, missing, returning devices) and the five most recent scans.
- Trigger scans programmatically with `POST /api/scan`, fetch the latest state at `GET /api/last-scan`, monitor service health with `GET /api/health`, look up individual devices via `GET /api/device/<ip>`, or read the full history via `GET /api/history`.

## Scan History & Notifications

- Every scan is appended to `data/scan_history.json` (configurable) with a compact summary.
- The CLI and web UI mark brand-new devices, highlight systems that reappear, and flag hosts that vanished since the previous run.
- Use `--notify-changes` (CLI) or the built-in web notifications to surface these events immediately.
- Export the structured JSON history or use the CSV exporter for spreadsheet-friendly diffs.
- Webhook payloads include the full scan summary alongside change metadata for easy integration with Slack/Teams/custom receivers.
- Webhooks fire on every scan run (with a "no change" notice when applicable) to keep dashboards in sync.

## Production Deployment

- Run the CLI under a process manager (systemd, supervisord) with your custom config file.
- Deploy the web app behind a reverse proxy (nginx, Caddy) and a production WSGI server:

  ```bash
  gunicorn web.wsgi:app --bind 0.0.0.0:8000 --workers 4
  ```

- Configure TLS and access control at the proxy layer; the included `web.require_auth` & `web.auth_token` fields are hooks for simple token enforcement when paired with middleware.


