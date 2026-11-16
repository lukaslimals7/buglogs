#!/usr/bin/env bash
# Rebuild the database and the markdown wiki from the public CSV.
set -euo pipefail
cd "$(dirname "$0")"
python3 -m kb.ingest
python3 -m kb.wiki
echo "KB rebuilt: data/kb.db + wiki/"
