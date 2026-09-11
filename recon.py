#!/usr/bin/env python3
"""
PerimeterDiff - Stage 1: Recon
Wraps subfinder to enumerate subdomains for a target and stores them
as a scan snapshot in SQLite for later diffing.
"""

import argparse
import json
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone


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


def run_subfinder(target, timeout=120):
    """Run subfinder in silent JSON mode and return list of (subdomain, source)."""
    cmd = ["subfinder", "-d", target, "-silent", "-oJ"]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
    except FileNotFoundError:
        print("[!] subfinder not found on PATH. Install it first: "
              "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
              file=sys.stderr)
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print(f"[!] subfinder timed out after {timeout}s for {target}", file=sys.stderr)
        sys.exit(1)

    if result.returncode != 0 and not result.stdout:
        print(f"[!] subfinder failed: {result.stderr.strip()}", file=sys.stderr)
        sys.exit(1)

    findings = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            host = obj.get("host")
            source = obj.get("source", "unknown")
        except json.JSONDecodeError:
            host = line
            source = "unknown"
        if host:
            findings.append((host, source))

    return findings


def store_scan(conn, target, findings):
    run_at = datetime.now(timezone.utc).isoformat()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO scans (target, stage, run_at) VALUES (?, ?, ?)",
        (target, "recon", run_at),
    )
    scan_id = cur.lastrowid

    cur.executemany(
        "INSERT INTO subdomains (scan_id, target, subdomain, source) VALUES (?, ?, ?, ?)",
        [(scan_id, target, host, source) for host, source in findings],
    )
    conn.commit()
    return scan_id


def main():
    parser = argparse.ArgumentParser(description="PerimeterDiff Stage 1: Recon")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("--db", default="perimeterdiff.db", help="SQLite DB path")
    parser.add_argument("--timeout", type=int, default=120, help="subfinder timeout in seconds")
    args = parser.parse_args()

    conn = init_db(args.db)
    print(f"[*] Running subfinder against {args.domain} ...")
    findings = run_subfinder(args.domain, timeout=args.timeout)

    if not findings:
        print("[!] No subdomains found.")
        sys.exit(0)

    scan_id = store_scan(conn, args.domain, findings)
    print(f"[+] Scan #{scan_id}: stored {len(findings)} subdomains for {args.domain}")
    for host, source in sorted(findings):
        print(f"    {host}  ({source})")


if __name__ == "__main__":
    main()
