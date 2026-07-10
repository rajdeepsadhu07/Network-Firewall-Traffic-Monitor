# Personal Firewall

A network firewall dashboard built with FastAPI (Python) and vanilla JavaScript.
Run it on Linux with root to get real iptables blocking, or on any machine in demo mode.

## Features

- Block IPs, ports, and domains via iptables
- Scan LAN and discover connected devices (IP, MAC, hostname)
- Monitor live network connections and active processes
- Real-time traffic chart showing blocked packets over time
- File malware scanner (ClamAV or heuristic)
- Event log for all firewall actions
- Demo mode on macOS, real blocking on Linux with sudo

## Tech Stack

- **Backend:** Python, FastAPI, SQLite, psutil
- **Frontend:** Vanilla HTML/CSS/JavaScript, Canvas chart
- **Firewall:** iptables (Linux), pfctl (macOS)

## Run on Linux (real firewall)

Then open http://localhost:8000

Run on macOS (demo mode)
bash

cd backend
../.venv/bin/uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
