#!/usr/bin/env bash
# Double-click in macOS Finder to launch the OSINT Monster Local Web App in your browser!
set -e
cd "$(dirname "$0")"
exec python3 scripts/server.py --host 127.0.0.1 --port 8000 --auto-port --open
