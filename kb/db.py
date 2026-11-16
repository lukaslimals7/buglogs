"""SQLite storage for the disclosed-report KB.

One file, data/kb.db. Standard library only: sqlite3 with FTS5.
"""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB = ROOT / "data" / "kb.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS reports (
  id             INTEGER PRIMARY KEY,
  title          TEXT NOT NULL,
  program        TEXT,
  vuln_type      TEXT,
  class_id       TEXT,
  severity       TEXT,
  severity_guess TEXT,
  bounty         REAL,
  votes          INTEGER NOT NULL DEFAULT 0,
  link           TEXT,
  substate       TEXT,
  cve_ids        TEXT,
  asset_type     TEXT,
  asset          TEXT,
  disclosed_at   TEXT,
  submitted_at   TEXT,
  reporter       TEXT,
  body           TEXT,
  has_writeup    INTEGER NOT NULL DEFAULT 0,
  source         TEXT NOT NULL DEFAULT 'reddelexc',
  updated_at     TEXT
);
CREATE INDEX IF NOT EXISTS reports_program ON reports(program);
CREATE INDEX IF NOT EXISTS reports_class   ON reports(class_id);
CREATE INDEX IF NOT EXISTS reports_votes   ON reports(votes DESC);
CREATE INDEX IF NOT EXISTS reports_bounty  ON reports(bounty DESC);
CREATE INDEX IF NOT EXISTS reports_vuln    ON reports(vuln_type);

CREATE VIRTUAL TABLE IF NOT EXISTS reports_fts USING fts5(
  title, program, vuln_type, body,
  content='reports', content_rowid='id', tokenize='porter unicode61'
);
CREATE TRIGGER IF NOT EXISTS reports_fts_ai AFTER INSERT ON reports BEGIN
  INSERT INTO reports_fts(rowid, title, program, vuln_type, body)
  VALUES (new.id, new.title, new.program, new.vuln_type, new.body);
END;
CREATE TRIGGER IF NOT EXISTS reports_fts_ad AFTER DELETE ON reports BEGIN
  INSERT INTO reports_fts(reports_fts, rowid, title, program, vuln_type, body)
  VALUES ('delete', old.id, old.title, old.program, old.vuln_type, old.body);
END;
CREATE TRIGGER IF NOT EXISTS reports_fts_au AFTER UPDATE OF title, program, vuln_type, body ON reports BEGIN
  INSERT INTO reports_fts(reports_fts, rowid, title, program, vuln_type, body)
  VALUES ('delete', old.id, old.title, old.program, old.vuln_type, old.body);
  INSERT INTO reports_fts(rowid, title, program, vuln_type, body)
  VALUES (new.id, new.title, new.program, new.vuln_type, new.body);
END;

CREATE TABLE IF NOT EXISTS classes (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT,
  report_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS programs (
  name TEXT PRIMARY KEY, report_count INTEGER NOT NULL DEFAULT 0,
  with_bounty INTEGER NOT NULL DEFAULT 0, total_bounty REAL NOT NULL DEFAULT 0,
  votes INTEGER NOT NULL DEFAULT 0, top_class TEXT
);

CREATE TABLE IF NOT EXISTS report_tags (
  report_id INTEGER NOT NULL, tag TEXT NOT NULL,
  PRIMARY KEY (report_id, tag)
);
CREATE INDEX IF NOT EXISTS report_tags_tag ON report_tags(tag);

CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
"""


def db_path() -> Path:
    return Path(os.environ.get("H1KB_DB") or DEFAULT_DB)


def connect(path: str | Path | None = None) -> sqlite3.Connection:
    p = Path(path) if path else db_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(p, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode = WAL")
    con.execute("PRAGMA synchronous = NORMAL")
    con.executescript(SCHEMA)
    return con


def set_meta(con: sqlite3.Connection, k: str, v: str) -> None:
    con.execute(
        "INSERT INTO meta(k, v) VALUES(?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v",
        (k, str(v)),
    )


def get_meta(con: sqlite3.Connection, k: str, default: str | None = None) -> str | None:
    row = con.execute("SELECT v FROM meta WHERE k = ?", (k,)).fetchone()
    return row["v"] if row else default
