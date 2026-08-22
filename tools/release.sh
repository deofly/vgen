#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
REPOSITORY="$(cd "${SCRIPT_DIR}/.." && pwd -P)"

if [[ -x "${REPOSITORY}/.venv/bin/python" ]]; then
  PYTHON_BIN="${REPOSITORY}/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="$(command -v python3)"
else
  printf 'VGen release requires Python 3.11 or newer.\n' >&2
  exit 1
fi

exec "${PYTHON_BIN}" "${SCRIPT_DIR}/release.py" "$@"
