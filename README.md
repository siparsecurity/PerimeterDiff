# PerimeterDiff

Free, open source continuous attack surface monitoring tool by Sipar Security.

A free alternative to paid attack surface monitoring platforms. Tracks subdomains, open ports/services, and tech stack fingerprints over time, and diffs each scan against the last to flag what changed.

## Status

Stage 1 (Recon) complete. Wraps `subfinder` to enumerate subdomains and stores them as a scan snapshot in SQLite.
