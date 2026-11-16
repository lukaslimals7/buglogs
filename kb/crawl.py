"""Optional: fetch public report write-ups from HackerOne. No token.

OFF BY DEFAULT. A fresh clone has no report bodies; this fills them in.

    python3 -m kb.crawl --max 200     # try 200 reports, then stop
    python3 -m crawl                  # everything still missing

Politeness: one request every 1.1s, resumable (only reports with
has_writeup = 0 are tried), and it stops the moment HackerOne answers 403 or
429 so it never hammers the site. Only public pages are read.

States stored in reports.has_writeup:
    0  not tried yet
    1  write-up stored
    2  unavailable (private, restricted, or gone: 403/404/410)
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

from .db import connect, set_meta

JSON_URL = "https://hackerone.com/reports/{id}.json"
UA = "h1-kb-crawl/0.1 (personal knowledge base; contact: lukaslogs.xix@gmail.com)"
GAP = 1.1


def fetch(rid: int) -> tuple[int, dict | None]:
    req = urllib.request.Request(JSON_URL.format(id=rid), headers={
        "Accept": "application/json", "User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception as e:  # network blip: treat as transient
        return 0, None


def crawl(max_reports: int | None = None, gap: float = GAP) -> dict:
    con = connect()
    rows = con.execute(
        "SELECT id FROM reports WHERE has_writeup = 0 ORDER BY votes DESC, id DESC "
        + (f"LIMIT {int(max_reports)}" if max_reports else "")
    ).fetchall()
    ok = unavailable = 0
    for i, (rid,) in enumerate(rows, 1):
        status, j = fetch(rid)
        if status in (403, 429):
            print(f"  HackerOne answered {status} at report {rid}; stopping. Run again later.",
                  file=sys.stderr)
            break
        if status in (404, 410):
            with con:
                con.execute("UPDATE reports SET has_writeup = 2 WHERE id = ?", (rid,))
            unavailable += 1
            continue
        if status != 200 or not j:
            continue  # transient: try again on the next run
        sc = j.get("structured_scope") or {}
        with con:
            con.execute(
                """UPDATE reports SET
                     body = ?, vuln_type = COALESCE(?, vuln_type),
                     severity = COALESCE(?, severity),
                     substate = COALESCE(?, substate),
                     cve_ids = COALESCE(?, cve_ids),
                     reporter = COALESCE(?, reporter),
                     asset_type = COALESCE(?, asset_type),
                     asset = COALESCE(?, asset),
                     disclosed_at = COALESCE(?, disclosed_at),
                     submitted_at = COALESCE(?, submitted_at),
                     has_writeup = 1,
                     updated_at = ?
                   WHERE id = ?""",
                (j.get("vulnerability_information"),
                 (j.get("weakness") or {}).get("name"),
                 j.get("severity_rating"),
                 j.get("substate"),
                 json.dumps(j.get("cve_ids") or []),
                 (j.get("reporter") or {}).get("username"),
                 sc.get("asset_type"), sc.get("asset_identifier"),
                 j.get("disclosed_at"), j.get("submitted_at"),
                 datetime.now(timezone.utc).isoformat(timespec="seconds"), rid),
            )
        ok += 1
        if ok % 25 == 0:
            print(f"  {ok} write-ups saved ({i} tried)", flush=True)
        time.sleep(gap)
    with con:
        set_meta(con, "crawled_at", datetime.now(timezone.utc).isoformat(timespec="seconds"))
    return {"tried": len(rows), "saved": ok, "unavailable": unavailable,
            "remaining": con.execute("SELECT COUNT(*) FROM reports WHERE has_writeup = 0").fetchone()[0]}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Fetch public write-ups (optional, no token).")
    ap.add_argument("--max", type=int, help="try at most N reports")
    ap.add_argument("--gap", type=float, default=GAP, help="seconds between requests")
    a = ap.parse_args(argv)
    s = crawl(a.max, a.gap)
    print(f"crawl: {s['saved']} saved, {s['unavailable']} unavailable, "
          f"{s['remaining']} still untried")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
