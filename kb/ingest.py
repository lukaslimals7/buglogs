"""Import the reddelexc/hackerone-reports CSV into data/kb.db.

    python3 -m kb.ingest                      # download the CSV, then import
    python3 -m kb.ingest --csv data/h1data.csv
    python3 -m kb.ingest --limit 500          # quick test on the first rows

No HackerOne account, no token: the CSV is a public GitHub dataset.
"""
from __future__ import annotations

import argparse
import csv
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from .db import ROOT, connect, set_meta
from .classify import ALL, class_of, guess_severity, guess_weakness

CSV_URL = "https://raw.githubusercontent.com/reddelexc/hackerone-reports/master/data.csv"
UA = "h1-kb-ingest/0.1"
DATA_DIR = ROOT / "data"

UPSERT = """
INSERT INTO reports (id, title, program, vuln_type, class_id, severity_guess, bounty, votes, link, source, updated_at)
VALUES (?,?,?,?,?,?,?,?,?,'reddelexc',?)
ON CONFLICT(id) DO UPDATE SET
  title=excluded.title, program=excluded.program, vuln_type=excluded.vuln_type,
  class_id=excluded.class_id, severity_guess=excluded.severity_guess,
  bounty=excluded.bounty, votes=excluded.votes, link=excluded.link,
  updated_at=excluded.updated_at
"""


def download(dest: Path | None = None) -> Path:
    dest = dest or (DATA_DIR / "h1data.csv")
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(CSV_URL, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=120) as r:
        dest.write_bytes(r.read())
    return dest


def _num(s: str | None, cast):
    try:
        return cast(float(s)) if s not in (None, "") else None
    except (TypeError, ValueError):
        return None


def read_rows(path: Path):
    with path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            m = re.search(r"(\d{4,})", row.get("link") or "")
            title = (row.get("title") or "").strip()
            if not m or not title:
                continue
            yield {
                "id": int(m.group(1)),
                "title": title,
                "program": (row.get("program") or "").strip() or None,
                "vuln_type": (row.get("vuln_type") or "").strip() or None,
                "votes": int(_num(row.get("upvotes"), float) or 0),
                "bounty": _num(row.get("bounty"), float),
            }


def ingest(csv_path: Path, limit: int | None = None) -> dict:
    con = connect()
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    n = 0
    with con:
        for row in read_rows(csv_path):
            if limit is not None and n >= limit:
                break
            weak = row["vuln_type"] or guess_weakness(row["title"])
            cls = class_of(weak)
            con.execute(
                UPSERT,
                (row["id"], row["title"], row["program"], row["vuln_type"], cls["id"],
                 guess_severity(row["title"]), row["bounty"], row["votes"],
                 f"https://hackerone.com/reports/{row['id']}", now),
            )
            n += 1
            if n % 2000 == 0:
                print(f"  {n} rows", flush=True)

        # Aggregates.
        con.executescript(
            """
            DELETE FROM programs;
            INSERT INTO programs(name, report_count, with_bounty, total_bounty, votes)
            SELECT COALESCE(program, '(unknown)'), COUNT(*),
                   SUM(CASE WHEN bounty > 0 THEN 1 ELSE 0 END),
                   COALESCE(SUM(bounty), 0), SUM(votes)
            FROM reports GROUP BY COALESCE(program, '(unknown)');
            UPDATE programs SET top_class = (
              SELECT class_id FROM reports r
              WHERE COALESCE(r.program, '(unknown)') = programs.name
              GROUP BY class_id ORDER BY COUNT(*) DESC, class_id LIMIT 1
            );
            DELETE FROM classes;
            """
        )
        for c in ALL:
            cnt = con.execute("SELECT COUNT(*) FROM reports WHERE class_id = ?", (c["id"],)).fetchone()[0]
            con.execute(
                "INSERT INTO classes(id, name, description, report_count) VALUES(?,?,?,?)",
                (c["id"], c["name"], c["desc"], cnt),
            )
        # Safety net: rebuild the full-text index from the table itself.
        con.execute("INSERT INTO reports_fts(reports_fts) VALUES('rebuild')")
        set_meta(con, "ingested_at", now)
        set_meta(con, "source", CSV_URL)

    stats = {
        "rows": con.execute("SELECT COUNT(*) FROM reports").fetchone()[0],
        "with_bounty": con.execute("SELECT COUNT(*) FROM reports WHERE bounty > 0").fetchone()[0],
        "programs": con.execute("SELECT COUNT(*) FROM programs").fetchone()[0],
        "classes": con.execute("SELECT COUNT(*) FROM classes").fetchone()[0],
        "by_class": con.execute(
            "SELECT c.id, c.name, c.report_count FROM classes c ORDER BY c.report_count DESC LIMIT 12"
        ).fetchall(),
        "top_programs": con.execute(
            "SELECT name, report_count, total_bounty FROM programs ORDER BY report_count DESC LIMIT 8"
        ).fetchall(),
    }
    return stats


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Import the public HackerOne report list into SQLite.")
    ap.add_argument("--csv", type=Path, help="use a local CSV instead of downloading")
    ap.add_argument("--limit", type=int, help="import at most N rows")
    ap.add_argument("--no-download", action="store_true", help="fail if the local CSV is missing")
    a = ap.parse_args(argv)

    path = a.csv or (DATA_DIR / "h1data.csv")
    if not path.exists():
        if a.no_download and not a.csv:
            print(f"missing {path}; pass --csv or drop --no-download", file=sys.stderr)
            return 2
        print(f"downloading {CSV_URL}", flush=True)
        path = download(path)

    stats = ingest(path, a.limit)
    print(f"imported {stats['rows']} reports | {stats['programs']} programs | "
          f"{stats['with_bounty']} with bounty", flush=True)
    print("\ntop classes", flush=True)
    for r in stats["by_class"]:
        print(f"  {r['id']:<6} {r['report_count']:>6}  {r['name']}", flush=True)
    print("\ntop programs", flush=True)
    for r in stats["top_programs"]:
        money = f"${r['total_bounty']:,.0f}" if r["total_bounty"] else "-"
        print(f"  {r['report_count']:>5} reports  {money:>12}  {r['name']}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
