"""Minimal search UI over the KB. Standard library only.

    python3 -m kb.server              # http://127.0.0.1:8765
    python3 -m kb.server --port 9000

Routes:
    GET /                     search page
    GET /api/search           JSON search (q, class, program, limit, offset)
    GET /api/report?id=       one report as JSON
    GET /api/stats            counts and filters for the UI
    GET /report/<id>          one report as HTML
    GET /wiki/<path>          a generated markdown file
"""
from __future__ import annotations

import argparse
import html
import json
import re
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .db import ROOT, connect

PUBLIC = ROOT / "public"
WIKI = ROOT / "wiki"
DEFAULT_PORT = 8765
ASSETS = PUBLIC / "assets"

COLS = ("r.id, r.title, r.program, r.vuln_type, r.class_id, r.severity, r.severity_guess, "
        "r.bounty, r.votes, r.link, r.has_writeup, r.body, r.reporter, r.substate")


def fts_query(q: str) -> str | None:
    """Turn free text into a safe FTS5 MATCH: quoted prefix terms, ANDed."""
    toks = re.findall(r"[A-Za-z0-9_]+", q or "")
    if not toks:
        return None
    return " AND ".join(f'"{t}"*' for t in toks)


def search(con, q: str = "", cls: str | None = None, program: str = "",
           limit: int = 25, offset: int = 0) -> tuple[int, list[dict]]:
    where: list[str] = []
    args: list = []
    join = ""
    match = fts_query(q)
    if match:
        join = "JOIN reports_fts f ON f.rowid = r.id"
        where.append("reports_fts MATCH ?")
        args.append(match)
    if cls:
        where.append("r.class_id = ?")
        args.append(cls)
    if program:
        where.append("r.program LIKE ?")
        args.append(f"%{program}%")
    w = ("WHERE " + " AND ".join(where)) if where else ""
    base = f"FROM reports r {join} {w}"
    total = con.execute(f"SELECT COUNT(*) {base}", args).fetchone()[0]
    rows = con.execute(
        f"SELECT {COLS} {base} ORDER BY r.votes DESC, r.bounty DESC LIMIT ? OFFSET ?",
        args + [limit, offset],
    ).fetchall()
    return total, [dict(r) for r in rows]


def stats(con) -> dict:
    return {
        "rows": con.execute("SELECT COUNT(*) FROM reports").fetchone()[0],
        "with_bounty": con.execute("SELECT COUNT(*) FROM reports WHERE bounty > 0").fetchone()[0],
        "programs": con.execute("SELECT COUNT(*) FROM programs").fetchone()[0],
        "classes": [dict(r) for r in con.execute(
            "SELECT id, name, report_count FROM classes ORDER BY report_count DESC")],
        "top_programs": [dict(r) for r in con.execute(
            "SELECT name, report_count, total_bounty FROM programs ORDER BY report_count DESC LIMIT 12")],
    }


def _report_html(r: dict) -> str:
    e = html.escape
    bits = []
    if r.get("program"):
        bits.append(f'<a href="/?program={urllib.parse.quote(r["program"])}">{e(r["program"])}</a>')
    if r.get("vuln_type"):
        bits.append(e(r["vuln_type"]))
    if r.get("severity") or r.get("severity_guess"):
        bits.append(e(r.get("severity") or r["severity_guess"]))
    body = r.get("body")
    body_html = f"<pre>{e(body)}</pre>" if body else (
        "<p><em>No write-up stored. Run <code>python3 -m kb.crawl</code> "
        "to fetch public write-ups.</em></p>")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(r['title'])} — CVE-logs</title>
<script>
  // theme before first paint: saved choice, else the OS preference
  (function(){{
    var saved = localStorage.getItem('cvelogs-theme');
    var dark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    document.documentElement.setAttribute('data-theme', saved || (dark ? 'dark' : 'light'));
  }})();
</script>
<style>
html{{background:#fcefcf}}
html[data-theme="dark"]{{background:#0a0a0a}}
body{{text-align:center;max-width:650px;margin:0 auto;padding:12px;
font-family:Verdana,Geneva,"DejaVu Sans",sans-serif;font-size:14px;color:#000;background:#fcefcf}}
html[data-theme="dark"] body{{color:#eceae5;background:#0a0a0a}}
h1{{font-family:"Times New Roman",Times,serif;font-size:26px;margin:14px 0 8px;text-align:left}}
nav{{display:inline-flex;flex-wrap:wrap;gap:12px;padding:12px;justify-content:center;
border-bottom:1.5px solid #000;margin-bottom:14px}}
html[data-theme="dark"] nav{{border-bottom-color:#eceae5}}
a{{color:#044c9f}} a:hover{{color:#000}}
html[data-theme="dark"] a{{color:#8ab4f8}} html[data-theme="dark"] a:hover{{color:#eceae5}}
.box{{border:1px solid #000;padding:10px;margin:12px 0;text-align:left;background:#fff8e6}}
html[data-theme="dark"] .box{{border-color:#eceae5;background:#111110}}
pre{{text-align:left;background:#fff;border:1px solid #000;padding:10px;overflow:auto;
white-space:pre-wrap;font-size:13px}}
html[data-theme="dark"] pre{{background:#0f0f0e;border-color:#eceae5;color:#eceae5}}
.meta{{text-align:left;font-size:13px;margin:4px 0}}
.theme-toggle{{font-size:11px;letter-spacing:.08em;text-transform:uppercase;padding:4px 10px}}
.back{{display:inline-block;margin-bottom:12px}}
</style></head><body>
<nav><a href="/">Search</a><a href="/wiki/index.md">Wiki</a>
<button class="theme-toggle" id="theme-toggle" type="button" aria-label="Switch theme">Dark</button></nav>
<script>
  (function(){{
    var btn = document.getElementById('theme-toggle');
    var sync = function() {{
      btn.textContent = document.documentElement.getAttribute('data-theme') === 'dark' ? 'Light' : 'Dark';
    }};
    sync();
    btn.addEventListener('click', function() {{
      var next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      localStorage.setItem('cvelogs-theme', next);
      sync();
    }});
  }})();
</script>
<h1>{e(r['title'])}</h1>
<p class="meta">Report #{r['id']} · {e(r.get('class_id') or '')}</p>
<p class="meta">{' · '.join(bits)}</p>
<p class="meta">Bounty: {f"${r['bounty']:,.0f}" if r.get('bounty') else '-'} ·
Votes: {r['votes']:,}</p>
<p class="meta"><a href="{e(r['link'])}">{e(r['link'])} ↗</a></p>
{body_html}
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "h1kb/0.1"
    con = None  # set by run()

    def log_message(self, *a):  # quiet
        pass

    def _send(self, code: int, body, ctype: str = "application/json; charset=utf-8") -> None:
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        u = urllib.parse.urlparse(self.path)
        path, qs = u.path, urllib.parse.parse_qs(u.query)
        try:
            if path in ("/", "/index.html"):
                return self._send(200, (PUBLIC / "index.html").read_bytes(),
                                  "text/html; charset=utf-8")
            if path == "/api/search":
                total, rows = search(
                    self.con,
                    (qs.get("q") or [""])[0],
                    (qs.get("class") or [""])[0] or None,
                    (qs.get("program") or [""])[0],
                    min(100, max(1, int((qs.get("limit") or ["25"])[0]))),
                    max(0, int((qs.get("offset") or ["0"])[0])),
                )
                return self._send(200, {"total": total, "results": rows})
            if path == "/api/report":
                rid = int((qs.get("id") or ["0"])[0])
                r = self.con.execute(f"SELECT {COLS} FROM reports r WHERE r.id = ?", (rid,)).fetchone()
                if not r:
                    return self._send(404, {"error": "not found"})
                return self._send(200, dict(r))
            if path == "/api/stats":
                return self._send(200, stats(self.con))
            if path.startswith("/report/"):
                r = self.con.execute(
                    f"SELECT {COLS} FROM reports r WHERE r.id = ?",
                    (int(path.rsplit("/", 1)[1]),),
                ).fetchone()
                if not r:
                    return self._send(404, b"not found", "text/plain; charset=utf-8")
                return self._send(200, _report_html(dict(r)), "text/html; charset=utf-8")
            if path.startswith("/assets/"):
                return self._asset(path[len("/assets/"):])
            if path.startswith("/wiki/"):
                return self._wiki(path[len("/wiki/"):])
            return self._send(404, {"error": "not found"})
        except Exception as exc:  # keep the UI alive
            return self._send(500, {"error": str(exc)})

    def _asset(self, rel: str) -> None:
        target = (ASSETS / rel).resolve()
        if not str(target).startswith(str(ASSETS.resolve())) or not target.is_file():
            return self._send(404, {"error": "not found"})
        types = {".webp": "image/webp", ".png": "image/png", ".jpg": "image/jpeg",
                 ".svg": "image/svg+xml", ".ico": "image/x-icon"}
        ctype = types.get(target.suffix.lower(), "application/octet-stream")
        return self._send(200, target.read_bytes(), ctype)

    def _wiki(self, rel: str) -> None:
        target = (WIKI / rel).resolve()
        if not str(target).startswith(str(WIKI.resolve())) or not target.is_file():
            return self._send(404, {"error": "not found"})
        ctype = "text/markdown; charset=utf-8" if target.suffix == ".md" else "text/plain; charset=utf-8"
        return self._send(200, target.read_bytes(), ctype)


def run(port: int = DEFAULT_PORT) -> None:
    Handler.con = connect()
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"h1-kb search UI: http://127.0.0.1:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Serve the local search UI.")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    a = ap.parse_args(argv)
    run(a.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
