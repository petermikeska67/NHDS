# Network Health & Device Scanner (MVP)

A lightweight command-line tool that discovers the devices on your local IPv4 network, checks their reachability, and presents the results in a readable table or JSON payload. Perfect for quickly answering _“Who’s on my Wi-Fi, and are they online?”_

## Features

- Auto-detects your local `/24` subnet (or target a custom CIDR).
- Concurrently pings hosts to determine reachability and latency.
- Resolves hostnames, fetches MAC addresses from ARP, and maps vendors via OUI prefixes.
- Renders a Rich-powered table with online/offline status indicators.
- Ships with a minimalist Flask web UI for ad-hoc scans and per-host ping tests.
- Optional live refresh mode for continuous monitoring.
- JSON output for scripting or integration.
- Web Interface
## Requirements

- Python 3.9 or newer.
- `ping` and `arp` commands available on the system (macOS, Linux, and Windows are supported).
- Optional: elevated privileges can improve ARP accuracy on some systems.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows, use `.venv\Scripts\activate`
pip install -r requirements.txt
```

## Usage

```bash
python main.py [options]
```

Common options:

- `--cidr 192.168.0.0/24` – scan a specific network instead of the auto-detected one.
- `--concurrency 128` – adjust concurrent probes (default: 64).
- `--timeout 1.5` – ping timeout per host in seconds.
- `--interval 30` – re-run the scan every _n_ seconds with a live-updating table.
- `--json` – emit JSON instead of a table (no refresh).
- `--vendor-file path/to/custom.json` – supply your own MAC prefix map.

Example session:

```bash
python main.py --interval 30
```

Example output:

```
┏━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━┓
┃ IP           ┃ Hostname    ┃ MAC              ┃ Vendor         ┃ Latency┃ Status   ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━┩
│ 192.168.1.1  │ Router      │ 40:B0:76:12:34:56│ TP-Link        │ 2.0 ms │  Online │
│ 192.168.1.42 │ Desktop-PC  │ D4:6D:6D:98:76:54│ Apple          │ 15.4 ms│  Online │
│ 192.168.1.99 │ —           │ —                │ Unknown        │ —      │  Offline│
└──────────────┴─────────────┴──────────────────┴────────────────┴────────┴──────────┘
Hosts scanned: 254 • Online: 2 • Duration: 3.12s • Started: 2024-05-27T18:13:42.123456Z
```

## Web Interface

Fire up the Flask app to run scans from your browser, re-test individual hosts, and download the latest results as JSON.

```bash
export FLASK_APP=web.app
flask run
# or: python -m flask --app web.app run
```

Then visit `http://127.0.0.1:5000/` to:

- Launch full-network scans with custom concurrency and timeouts.
- Run on-demand ping tests for any discovered device.
- Save the most recent scan as a JSON file via the UI.
- Trigger scans programmatically with `POST /api/scan` or fetch the latest result from `GET /api/last-scan`.
