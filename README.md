# PerimeterDiff

Free, open source continuous attack surface monitoring tool by Sipar Security.

A free alternative to paid attack surface monitoring platforms. Tracks subdomains, open ports/services, and tech stack fingerprints over time, and diffs each scan against the last to flag what changed.

## Status

Stages 1 and 2 complete. Recon wraps `subfinder` to enumerate subdomains; Probe wraps `httpx` to find which are live and capture HTTP response data. Both store snapshots in SQLite.

## Stages

1. Recon: subfinder wrapper, baseline subdomains in SQLite (done)
2. Probe: httpx wrapper, live host check, status codes, titles (done)
3. Fingerprint: nmap ports + tech stack detection
4. Diff engine: compares current scan to last snapshot, flags new/removed/changed assets
5. Report/alert: CLI output, JSON export, optional webhook

## Usage

```bash
# Stage 1: enumerate subdomains
python3 recon.py -d example.com

# Stage 2: probe them for live hosts
python3 probe.py -d example.com
```

Requires [subfinder](https://github.com/projectdiscovery/subfinder) and [httpx](https://github.com/projectdiscovery/httpx) on PATH.
