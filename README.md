# Week 03 — Python Security

Hardened security scripts covering hashing, password storage, file integrity,
port scanning, network sweeping, and packet crafting.

## Structure
- `scripts/` — individual tool scripts (W3-01 to W3-09)
- `tools/` — unified CLI entry point
- `tests/` — test suite
- `wordlists/` — demo wordlist (fake entries only)

## Setup
```bash
python -m venv env
source env/bin/activate
pip install -r requirements.txt
cp .env.example .env
# edit .env and set DEMO_PASSWORD
```

## Usage
```bash
python tools/security_toolkit.py --help
```

## Security
All scripts pass `bandit -r . --exclude ./env -ll` with zero MEDIUM or HIGH findings.
Run with `sudo` where raw socket access is required (scan, sweep, scapy).

## Warning
Authorized use only. Never run against systems you do not own.
