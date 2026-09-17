#!/usr/bin/env python3
"""
PerimeterDiff - Stage 2: Probe
Takes subdomains from the latest recon scan, runs them through httpx to
find which are live, and stores the HTTP response data as a probe snapshot.

Usage:
    python3 probe.py -d example.com
    python3 probe.py -d example.com --scan-id 3
    python3 probe.py -d example.com --db perimeterdiff.db
"""

import argparse
import json
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone

from recon import SCHEMA as RECON_SCHEMA


PROBE_SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    target TEXT NOT NULL,
    subdomain TEXT NOT NULL,
    url TEXT,
    status_code INTEGER,
    title TEXT,
    webserver TEXT,
    content_length INTEGER,
    FOREIGN KEY (scan_id) REFERENCES scans (id)
);

CREATE INDEX IF NOT EXISTS idx_hosts_target ON hosts (target);
CREATE INDEX IF NOT EXISTS idx_hosts_scan ON hosts (scan_id);
"""


def init_probe_db(db_path):
    """Ensure both recon and probe tables exist, so probe can run on any DB."""
    conn = sqlite3.connect(db_path)
    conn.executescript(RECON_SCHEMA)
    conn.executescript(PROBE_SCHEMA)
    conn.commit()
    return conn


def get_latest_recon_scan(conn, target):
    """Return the most recent recon scan_id for a target, or None."""
    cur = conn.cursor()
    cur.execute(
        "SELECT id FROM scans WHERE target = ? AND stage = 'recon' "
        "ORDER BY id DESC LIMIT 1",
        (target,),
    )
    row = cur.fetchone()
    return row[0] if row else None


def load_subdomains(conn, scan_id):
    """Return the list of subdomains stored under a given recon scan."""
    cur = conn.cursor()
    cur.execute(
        "SELECT DISTINCT subdomain FROM subdomains WHERE scan_id = ?",
        (scan_id,),
    )
    return [row[0] for row in cur.fetchall()]


def run_httpx(subdomains, timeout=300, threads=50):
    """Feed subdomains to httpx via stdin, return parsed live host records."""
    cmd = [
        "httpx",
        "-silent",
        "-json",
        "-status-code",
        "-title",
        "-web-server",
        "-content-length",
        "-follow-redirects",
        "-threads", str(threads),
    ]

    stdin_data = "\n".join(subdomains)

    try:
        result = subprocess.run(
            cmd,
            input=stdin_data,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        print("[!] httpx not found on PATH. Install it first: "
              "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
              file=sys.stderr)
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print(f"[!] httpx timed out after {timeout}s", file=sys.stderr)
        sys.exit(1)

    if result.returncode != 0 and not result.stdout:
        print(f"[!] httpx failed: {result.stderr.strip()}", file=sys.stderr)
        sys.exit(1)

    return parse_httpx_output(result.stdout)


def parse_httpx_output(raw_output):
    """Parse httpx JSONL output into normalised host records."""
    hosts = []
    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        subdomain = obj.get("input") or obj.get("host") or ""
        if not subdomain:
            continue

        hosts.append({
            "subdomain": subdomain,
            "url": obj.get("url"),
            "status_code": obj.get("status_code"),
            "title": obj.get("title"),
            "webserver": obj.get("webserver"),
            "content_length": obj.get("content_length"),
        })

    return hosts
