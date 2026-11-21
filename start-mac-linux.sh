#!/bin/sh
set -e
cd "$(dirname "$0")"
PY=python3
command -v "$PY" >/dev/null || { echo 'Python 3.11+ is required'; exit 1; }
"$PY" -c 'import sys; assert sys.version_info >= (3,11), "Python 3.11+ required"'
# No dependencies installed. Run from this directory as the import root.
"$PY" -m locdepintel serve "$@"
