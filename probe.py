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
