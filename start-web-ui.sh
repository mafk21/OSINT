#!/usr/bin/env bash
# Launch the OSINT Monster Local Web App and open it automatically in your default browser!
set -e
cd "$(dirname "$0")"
exec python3 scripts/server.py --host 127.0.0.1 --port 8000 --auto-port --open "$@"
