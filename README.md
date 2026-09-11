# PerimeterDiff

Free, open source continuous attack surface monitoring tool by Sipar Security.

A free alternative to paid attack surface monitoring platforms. Tracks subdomains, open ports/services, and tech stack fingerprints over time, and diffs each scan against the last to flag what changed.

## Status

Stage 1 (Recon) complete. Wraps `subfinder` to enumerate subdomains and stores them as a scan snapshot in SQLite.

## Stages

1. Recon: subfinder wrapper, baseline subdomains in SQLite (done)
2. Probe: httpx wrapper, live host check, status codes, titles
3. Fingerprint: nmap ports + tech stack detection
4. Diff engine: compares current scan to last snapshot, flags new/removed/changed assets
5. Report/alert: CLI output, JSON export, optional webhook
