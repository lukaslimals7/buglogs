# Data provenance

This repository ships **code** and **generated markdown**. The report data is
not mine and is not relicensed. Here is exactly where every piece comes from.

## Report list (the base dataset)

- **Source:** <https://github.com/reddelexc/hackerone-reports>
- **File:** `data.csv`, fetched from
  `https://raw.githubusercontent.com/reddelexc/hackerone-reports/master/data.csv`
- **Fields used:** `program`, `title`, `link`, `upvotes`, `bounty`, `vuln_type`
- **Licence/credit:** a community compilation of **publicly disclosed** HackerOne
  reports. Report titles and write-ups belong to their **authors** and to the
  **programs** that disclosed them. Credit: reddelexc and contributors.
- Fetched by `python3 -m kb.ingest`. **No HackerOne account and no API token.**

## Report write-ups (optional, off by default)

- **Source:** each report's public page on HackerOne,
  `https://hackerone.com/reports/<id>.json`
- **No token.** Public pages only. Polite, resumable crawler:
  `python3 -m kb.crawl`.
- **Not run by default**, so a fresh clone contains no report bodies.
- Private or restricted reports return 403/404 and are skipped, not retried.

## Vulnerability taxonomy

- The class mapping is **written for this project** from the public weakness
  names themselves (the CWE titles and OWASP categories HackerOne uses).
- It is **not** derived from, copied from, or credited to any other project.
- The class ids (XSS, CSRF, SSRF, …) are short, conventional abbreviations.

## Code

- **MIT**, see [LICENSE](LICENSE). Copyright (c) 2026 Lukas Lima.

## What this is not

- Not affiliated with, sponsored, or endorsed by HackerOne.
- Not a complete or real-time dataset: it is a snapshot of a public dataset at
  ingest time. Re-run `python3 -m kb.ingest` to refresh.
- Report content is provided for study and reference. If you republish it,
  credit the authors and the programs, and respect each program's disclosure
  terms.

## Regenerating everything

```bash
python3 -m kb.ingest     # fetch the CSV, build data/kb.db (SQLite + FTS5)
python3 -m kb.wiki       # build the markdown wiki under wiki/
python3 -m kb.server     # search UI on http://127.0.0.1:8765
# optional, off by default:
python3 -m kb.crawl      # public write-ups, polite and resumable
```
