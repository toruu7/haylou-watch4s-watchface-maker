#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
echo "Starting Haylou Watch 4S Studio..."
python3 studio/server.py
