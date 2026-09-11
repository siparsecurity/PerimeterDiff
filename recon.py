#!/usr/bin/env python3
"""
PerimeterDiff - Stage 1: Recon
Wraps subfinder to enumerate subdomains for a target and stores them
as a scan snapshot in SQLite for later diffing.
"""

import sqlite3


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    stage TEXT NOT NULL,
    run_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS subdomains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    target TEXT NOT NULL,
    subdomain TEXT NOT NULL,
    source TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans (id)
);

CREATE INDEX IF NOT EXISTS idx_subdomains_target ON subdomains (target);
"""


def init_db(db_path):
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)
    conn.commit()
    return conn
