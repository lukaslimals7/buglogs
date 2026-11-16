"""Export data/kb.db to markdown in the llm-wiki layout.

    python3 -m kb.wiki                 # everything
    python3 -m kb.wiki --max-raw 2000  # cap the per-report files (faster)

Layout produced under wiki/:

    SCHEMA.md  index.md  log.md
    raw/reports/<id>.md         one immutable page per report
    concepts/<class>.md         one page per vulnerability class
    entities/<program>.md       one page per program
    queries/                    answers worth keeping, filed by hand or by an agent
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

from .db import ROOT, connect, get_meta
from .classify import ALL, OTHER

WIKI_DIR = ROOT / "wiki"


def slug(s: str) -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    return s.strip("-") or "unknown"


def fm(fields: dict) -> str:
    lines = ["---"]
    for k, v in fields.items():
        if v is None:
            continue
        if isinstance(v, (list, tuple)):
            lines.append(f"{k}: [" + ", ".join(str(x) for x in v) + "]")
        elif isinstance(v, bool):
            lines.append(f"{k}: {'true' if v else 'false'}")
        else:
            lines.append(f"{k}: {json.dumps(v, ensure_ascii=False)}")
    lines.append("---")
    return "\n".join(lines)


def _money(v) -> str:
    return f"${v:,.0f}" if v else "-"


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


# ---------------------------------------------------------------- SCHEMA / index / log

SCHEMA_MD = """# Wiki Schema

## Domain

Publicly disclosed HackerOne bug-bounty reports: what was reported, on which
program, in which vulnerability class, and what it paid. Built from the open
reddelexc/hackerone-reports dataset. No write-ups are stored unless the optional
crawler has been run.

Provenance: the report list comes from `reddelexc/hackerone-reports`; report
titles and write-ups belong to their authors and to the programs that disclosed
them. The code is MIT. See `../DATA_PROVENANCE.md`.

## Conventions

- File names: lowercase, hyphens, no spaces.
- Every page starts with YAML frontmatter (see below).
- Link between pages with `[[wikilinks]]`; a page links out at least twice.
- `raw/` is immutable source material. Never edit it; corrections go in the
  derived pages.
- Regenerate with `python3 -m kb.wiki`; do not hand-edit generated pages.

## Frontmatter

```yaml
---
title: Page title
created: YYYY-MM-DD
updated: YYYY-MM-DD
type: entity | concept | summary
tags: [vuln-class, program, ...]
reports: N          # entity / concept pages
---
```

## Tag taxonomy

- `vuln-class` — a vulnerability class page (concepts/)
- `program` — a bug-bounty program page (entities/)
- `report` — a single disclosed report (raw/reports/)
- `query` — a filed answer worth keeping (queries/)

## Page thresholds

- One `raw/reports/<id>.md` per report: they are the primary sources.
- One `concepts/<class>.md` per class, one `entities/<program>.md` per program.
- Create a `queries/` page only for an answer that would be painful to re-derive.
"""


def write_schema() -> None:
    _write(WIKI_DIR / "SCHEMA.md", SCHEMA_MD)


def write_index(con, today: str, counts: dict) -> None:
    rows = con.execute(
        "SELECT id, name, report_count FROM classes ORDER BY report_count DESC"
    ).fetchall()
    progs = con.execute(
        "SELECT name, report_count, total_bounty FROM programs ORDER BY report_count DESC LIMIT 40"
    ).fetchall()
    out = [
        "# H1 Disclosed Reports KB",
        "",
        f"> Generated from `reddelexc/hackerone-reports`. Last updated: {today}.",
        f"> Reports: {counts['rows']:,} · Programs: {counts['programs']:,} · "
        f"Classes: {counts['classes']} · With bounty: {counts['with_bounty']:,}.",
        "",
        "Read `SCHEMA.md` first. Search the same data at `/` (the local UI) or query "
        "`data/kb.db` directly.",
        "",
        "## Classes",
        "",
    ]
    for r in rows:
        out.append(f"- [[concepts/{slug(r['name'])}|{r['id']}]] {r['name']} — {r['report_count']:,}")
    out += ["", "## Programs", ""]
    for r in progs:
        out.append(f"- [[entities/{slug(r['name'])}|{r['name']}]] — {r['report_count']:,} reports, "
                   f"{_money(r['total_bounty'])} awarded")
    out += [
        "",
        "## Using this wiki",
        "",
        "- Start at a class page, then follow `[[raw/reports/...]]` links to individual reports.",
        "- Start at a program page to see what a target has paid for and how often.",
        "- File durable answers under `queries/`.",
        "",
    ]
    _write(WIKI_DIR / "index.md", "\n".join(out))


def append_log(con, today: str, counts: dict) -> None:
    path = WIKI_DIR / "log.md"
    if not path.exists():
        _write(path, "# Wiki Log\n\n> Chronological record. Append-only.\n")
    entry = (
        f"\n## [{today}] ingest | reddelexc/hackerone-reports\n"
        f"- Reports: {counts['rows']:,} · Programs: {counts['programs']:,} · "
        f"Classes: {counts['classes']}\n"
        f"- Files: `wiki/raw/reports/*.md`, `wiki/concepts/*.md`, `wiki/entities/*.md`\n"
    )
    with path.open("a", encoding="utf-8") as f:
        f.write(entry)


# ---------------------------------------------------------------- raw reports

def report_page(r, class_name: str, program_slug: str, class_slug: str) -> str:
    link = f"https://hackerone.com/reports/{r['id']}"
    out = [fm({
        "id": r["id"],
        "title": r["title"],
        "program": r["program"],
        "vuln_type": r["vuln_type"],
        "class": r["class_id"],
        "class_name": class_name,
        "severity_guess": r["severity_guess"],
        "bounty": r["bounty"],
        "votes": r["votes"],
        "link": link,
        "source": "reddelexc/hackerone-reports",
        "type": "report",
        "tags": ["report", r["class_id"]],
    }), "", f"# {r['title']}", ""]
    bits = []
    if r["program"]:
        bits.append(f"Program: [[entities/{program_slug}|{r['program']}]]")
    if r["vuln_type"]:
        bits.append(f"Weakness: {r['vuln_type']} ([[concepts/{class_slug}|{r['class_id']}]])")
    else:
        bits.append(f"Class: [[concepts/{class_slug}|{r['class_id']}]]")
    out.append(" · ".join(bits))
    out.append("")
    out.append(f"Bounty: {_money(r['bounty'])} · Votes: {r['votes']:,}")
    out.append("")
    out.append(f"Report: <{link}>")
    if r["body"]:
        out += ["", "## Write-up", "", r["body"]]
    out.append("")
    return "\n".join(out)


def write_raw_reports(con, today: str, max_raw: int | None) -> int:
    """One markdown file per report: raw/reports/<id>.md."""
    rows = con.execute(
        "SELECT id, title, program, vuln_type, class_id, severity_guess, bounty, votes, body "
        "FROM reports ORDER BY id"
    ).fetchall()
    if max_raw is not None:
        rows = rows[:max_raw]
    class_name = {c["id"]: c["name"] for c in ALL}
    written = 0
    for r in rows:
        path = WIKI_DIR / "raw" / "reports" / f"{r['id']}.md"
        _write(path, report_page(r, class_name.get(r["class_id"], r["class_id"]),
                                 slug(r["program"] or "unknown"), slug(class_name.get(r["class_id"], "other"))))
        written += 1
        if written % 2000 == 0:
            print(f"  {written} report pages", flush=True)
    return written


# ---------------------------------------------------------------- concepts / entities

def write_concepts(con, today: str) -> int:
    n = 0
    for c in ALL:
        rows = con.execute(
            "SELECT id, title, program, bounty, votes FROM reports WHERE class_id = ? "
            "ORDER BY votes DESC, bounty DESC LIMIT 25", (c["id"],)
        ).fetchall()
        progs = con.execute(
            "SELECT program, COUNT(*) n FROM reports WHERE class_id = ? AND program IS NOT NULL "
            "GROUP BY program ORDER BY n DESC LIMIT 8", (c["id"],)
        ).fetchall()
        total_bounty = con.execute(
            "SELECT COALESCE(SUM(bounty),0) s FROM reports WHERE class_id = ?", (c["id"],)
        ).fetchone()["s"]
        total = con.execute(
            "SELECT COUNT(*) n FROM reports WHERE class_id = ?", (c["id"],)
        ).fetchone()["n"]
        out = [fm({
            "title": c["name"], "class_id": c["id"], "created": today, "updated": today,
            "type": "concept", "tags": ["vuln-class"], "reports": total,
        }), "", f"# {c['name']}", "", c["desc"], ""]
        out.append(f"Reports in this class: {total:,} · Total awarded: {_money(total_bounty)}")
        out += ["", "## Most reported programs", ""]
        for p in progs:
            out.append(f"- [[entities/{slug(p['program'])}|{p['program']}]] — {p['n']:,}")
        out += ["", "## Top reports by votes", ""]
        for r in rows:
            prog = f", {r['program']}" if r["program"] else ""
            out.append(f"- [[raw/reports/{r['id']}|{r['id']}]] {r['title']}"
                       f"{prog} — {_money(r['bounty'])}, {r['votes']:,} votes")
        out.append("")
        _write(WIKI_DIR / "concepts" / f"{slug(c['name'])}.md", "\n".join(out))
        n += 1
    return n


def write_entities(con, today: str, min_reports: int = 1) -> int:
    progs = con.execute(
        "SELECT name, report_count, with_bounty, total_bounty, votes, top_class "
        "FROM programs WHERE report_count >= ? ORDER BY report_count DESC", (min_reports,)
    ).fetchall()
    n = 0
    for p in progs:
        name = p["name"]
        classes = con.execute(
            "SELECT class_id, COUNT(*) n FROM reports WHERE COALESCE(program,'(unknown)') = ? "
            "GROUP BY class_id ORDER BY n DESC LIMIT 6", (name,)
        ).fetchall()
        rows = con.execute(
            "SELECT id, title, vuln_type, bounty, votes FROM reports "
            "WHERE COALESCE(program,'(unknown)') = ? ORDER BY votes DESC, bounty DESC LIMIT 20",
            (name,),
        ).fetchall()
        out = [fm({
            "title": name, "created": today, "updated": today, "type": "entity",
            "tags": ["program"], "reports": p["report_count"],
        }), "", f"# {name}", "",
            f"Reports: {p['report_count']:,} · With bounty: {p['with_bounty']:,} · "
            f"Total awarded: {_money(p['total_bounty'])} · Votes: {p['votes']:,}", ""]
        out += ["## Top classes", ""]
        for c in classes:
            out.append(f"- [[concepts/{slug(c['class_id'])}|{c['class_id']}]] — {c['n']:,}")
        out += ["", "## Notable reports", ""]
        for r in rows:
            out.append(f"- [[raw/reports/{r['id']}|{r['id']}]] {r['title']} — "
                       f"{_money(r['bounty'])}, {r['votes']:,} votes")
        out.append("")
        _write(WIKI_DIR / "entities" / f"{slug(name)}.md", "\n".join(out))
        n += 1
    return n


def write_queries_readme() -> None:
    _write(WIKI_DIR / "queries" / "README.md",
           "# Queries\n\nAnswers worth keeping, filed here. See `../SCHEMA.md`.\n")


# ---------------------------------------------------------------- entry point

def build(max_raw: int | None = None, min_reports: int = 1) -> dict:
    con = connect()
    today = datetime.now(timezone.utc).date().isoformat()
    if WIKI_DIR.exists():
        shutil.rmtree(WIKI_DIR)
    WIKI_DIR.mkdir(parents=True, exist_ok=True)

    counts = {
        "rows": con.execute("SELECT COUNT(*) FROM reports").fetchone()[0],
        "programs": con.execute("SELECT COUNT(*) FROM programs").fetchone()[0],
        "classes": con.execute("SELECT COUNT(*) FROM classes").fetchone()[0],
        "with_bounty": con.execute("SELECT COUNT(*) FROM reports WHERE bounty > 0").fetchone()[0],
    }
    write_schema()
    write_index(con, today, counts)
    n_raw = write_raw_reports(con, today, max_raw)
    n_con = write_concepts(con, today)
    n_ent = write_entities(con, today, min_reports)
    write_queries_readme()
    append_log(con, today, counts)
    set_meta_safe(con, today)
    return {"raw": n_raw, "concepts": n_con, "entities": n_ent, **counts}


def set_meta_safe(con, today: str) -> None:
    from .db import set_meta
    set_meta(con, "wiki_built_at", today)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Export the SQLite KB to markdown.")
    ap.add_argument("--max-raw", type=int, help="write at most N per-report files")
    ap.add_argument("--min-reports", type=int, default=1, help="skip programs with fewer reports")
    a = ap.parse_args(argv)
    s = build(a.max_raw, a.min_reports)
    print(f"wiki: {s['raw']:,} report pages, {s['concepts']} concepts, "
          f"{s['entities']} program pages -> {WIKI_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
