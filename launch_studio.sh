#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v python3 >/dev/null 2>&1; then
  echo "[ERROR] python3 was not found. Install Python 3.9+ first." >&2
  exit 1
fi

if ! python3 -c 'import PIL' >/dev/null 2>&1; then
  echo "[*] Installing the Python dependency (Pillow)..."
  python3 -m pip install -r requirements.txt
fi

exec python3 studio/server.py
