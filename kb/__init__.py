"""H1 disclosed-report KB: CSV -> SQLite/FTS5 -> markdown wiki + search UI.

Standard library only. Layout (see README.md):

    kb/db.py       schema and connection
    kb/classify.py HackerOne weakness names -> vulnerability classes
    kb/ingest.py   reddelexc/hackerone-reports CSV -> data/kb.db
    kb/wiki.py     data/kb.db -> wiki/ (llm-wiki layout)
    kb/crawl.py    optional public write-up crawler (not run by default)
    kb/server.py   minimal search UI on localhost
"""
