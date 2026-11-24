#!/bin/sh
set -eu
cd -- "$(dirname -- "$0")"
exec python3 -E -s -B scripts/preflight.py "$@"
