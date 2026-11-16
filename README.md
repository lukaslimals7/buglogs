# CVE-logs

A searchable, markdown-first knowledge base of **publicly disclosed HackerOne
bug-bounty reports** — for you, and for your AI agents.

- Base data: the open [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) dataset.
- **No HackerOne account. No API token.**
- **Python standard library only** — nothing to install, nothing to break.
- Output: one SQLite file (`data/kb.db`) plus a markdown wiki (`wiki/`) in the
  [llm-wiki](https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f) layout.

## Quickstart

```bash
python3 -m kb.ingest     # fetch the CSV, build data/kb.db (SQLite + FTS5)
python3 -m kb.wiki       # build the markdown wiki under wiki/
python3 -m kb.server     # search UI on http://127.0.0.1:8765
```

Or run `./refresh.sh` to rebuild the database and the wiki in one go.

Python 3.11+ (uses `sqlite3` with FTS5, which ships with it).

## What you get

- **15,000+ reports** with title, program, weakness, bounty, votes and link.
- **18 vulnerability classes** (XSS, SSRF, SQLi, IDOR, RCE, …) derived from the
  HackerOne weakness names, with a title-based guess when a report has none.
- **Full-text search** over titles, programs and weaknesses.
- **A markdown wiki**: one page per report (`wiki/raw/reports/<id>.md`), one per
  class (`wiki/concepts/`), one per program (`wiki/entities/`), plus
  `index.md`, `SCHEMA.md` and `log.md`.
- **A minimal search UI** with a search box, class and program filters.

## Layout

```
kb/
  db.py       schema and connection (SQLite + FTS5)
  classify.py HackerOne weakness names -> vulnerability classes
  ingest.py   reddelexc/hackerone-reports CSV -> data/kb.db
  wiki.py     data/kb.db -> wiki/ (markdown)
  server.py   minimal search UI on localhost
  crawl.py    optional public write-up crawler (off by default)
public/index.html
data/         generated: kb.db, h1data.csv
wiki/         generated: raw/, concepts/, entities/, index.md, log.md
```

## Optional: write-ups

A fresh clone has **no report bodies**. If you want them, the public report
pages can be fetched without a token:

```bash
python3 -m kb.crawl --max 200     # try 200, then stop
python3 -m kb.crawl              # everything still missing
```

It is polite (one request every 1.1s), resumable, and stops on 403/429. Turn on
`kb.crawl` only if you actually want the bodies — the metadata KB is complete
without them.

## Query the data directly

```python
from kb.db import connect
con = connect()
rows = con.execute(
    "SELECT r.title, r.program, r.votes FROM reports_fts f "
    "JOIN reports r ON r.id = f.rowid "
    "WHERE reports_fts MATCH ? ORDER BY r.votes DESC LIMIT 10", ('"ssrf"*',)
).fetchall()
```

## License and provenance

- **Code:** MIT, see [LICENSE](LICENSE).
- **Data:** not mine and not relicensed. The report list comes from
  [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports);
  report titles and write-ups belong to their **authors** and the **programs**
  that disclosed them. See [DATA_PROVENANCE.md](DATA_PROVENANCE.md).

## Credits

- [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) — the report list.
- The report authors and the programs that disclosed them.
