"""Self-test: tiny CSV -> database -> search -> markdown wiki.

    cd ~/Desktop/h1-kb && python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from kb import wiki
from kb.db import connect
from kb.ingest import ingest
from kb.server import search

CSV = """program,title,link,upvotes,bounty,vuln_type
Acme,"SSRF in the export proxy",hackerone.com/reports/1001,12,500.0,Server-Side Request Forgery (SSRF)
Acme,"Reflected XSS in search",hackerone.com/reports/1002,7,0.0,Cross-site Scripting (XSS) - Reflected
Beta,"Weak password policy",hackerone.com/reports/1003,3,0.0,
"""


class KBTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.csv = self.dir / "tiny.csv"
        self.csv.write_text(CSV, encoding="utf-8")
        os.environ["H1KB_DB"] = str(self.dir / "kb.db")
        wiki.WIKI_DIR = self.dir / "wiki"

    def test_ingest_search_wiki(self):
        stats = ingest(self.csv)
        self.assertEqual(stats["rows"], 3)
        self.assertEqual(stats["programs"], 2)

        con = connect()
        self.assertEqual(con.execute("SELECT COUNT(*) FROM reports").fetchone()[0], 3)
        self.assertEqual(con.execute("SELECT class_id FROM reports WHERE id=1001").fetchone()[0], "SSRF")
        # no weakness in the CSV -> guessed from the title
        self.assertEqual(con.execute("SELECT class_id FROM reports WHERE id=1003").fetchone()[0], "AUTH")

        total, rows = search(con, "ssrf")
        self.assertGreaterEqual(total, 1)
        self.assertEqual(rows[0]["id"], 1001)

        s = wiki.build()
        self.assertEqual(s["raw"], 3)
        self.assertTrue((self.dir / "wiki" / "index.md").exists())
        self.assertTrue((self.dir / "wiki" / "raw" / "reports" / "1001.md").exists())
        self.assertTrue((self.dir / "wiki" / "concepts" / "server-side-request-forgery.md").exists())


if __name__ == "__main__":
    unittest.main()
