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


def store_probe(conn, target, hosts):
    """Create a probe scan row and store all live host records under it."""
    run_at = datetime.now(timezone.utc).isoformat()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO scans (target, stage, run_at) VALUES (?, ?, ?)",
        (target, "probe", run_at),
    )
    scan_id = cur.lastrowid

    cur.executemany(
        "INSERT INTO hosts (scan_id, target, subdomain, url, status_code, "
        "title, webserver, content_length) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (
                scan_id,
                target,
                h["subdomain"],
                h["url"],
                h["status_code"],
                h["title"],
                h["webserver"],
                h["content_length"],
            )
            for h in hosts
        ],
    )
    conn.commit()
    return scan_id


def main():
    parser = argparse.ArgumentParser(description="PerimeterDiff Stage 2: Probe")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("--db", default="perimeterdiff.db", help="SQLite DB path")
    parser.add_argument("--scan-id", type=int,
                        help="Recon scan ID to probe (default: latest)")
    parser.add_argument("--timeout", type=int, default=300,
                        help="httpx timeout in seconds")
    parser.add_argument("--threads", type=int, default=50,
                        help="httpx concurrency")
    args = parser.parse_args()

    conn = init_probe_db(args.db)

    scan_id = args.scan_id or get_latest_recon_scan(conn, args.domain)
    if scan_id is None:
        print(f"[!] No recon scan found for {args.domain}. Run recon.py first.",
              file=sys.stderr)
        sys.exit(1)

    subdomains = load_subdomains(conn, scan_id)
    if not subdomains:
        print(f"[!] Recon scan #{scan_id} has no subdomains stored.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Probing {len(subdomains)} subdomains from recon scan #{scan_id} ...")
    hosts = run_httpx(subdomains, timeout=args.timeout, threads=args.threads)

    if not hosts:
        print("[!] No live hosts found.")
        sys.exit(0)

    probe_scan_id = store_probe(conn, args.domain, hosts)
    print(f"[+] Probe scan #{probe_scan_id}: {len(hosts)} live of "
          f"{len(subdomains)} subdomains")

    for h in sorted(hosts, key=lambda x: x["subdomain"]):
        status = h["status_code"] if h["status_code"] is not None else "-"
        title = (h["title"] or "")[:50]
        print(f"    [{status}] {h['url'] or h['subdomain']}  {title}")


if __name__ == "__main__":
    main()
