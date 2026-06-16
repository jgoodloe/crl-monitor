#!/bin/bash
# SessionStart hook: install Python dependencies so the app, linters and any
# tests work in Claude Code on the web. Synchronous (no async) so deps are
# guaranteed ready before the session begins.
set -euo pipefail

# Only run in the remote (web) environment.
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "$CLAUDE_PROJECT_DIR"

# A dedicated virtualenv keeps installs off the distro's system site-packages
# (whose pip-unmanaged packages can otherwise break `pip install`). Idempotent:
# `venv` reuses an existing environment, and pip skips already-satisfied deps.
python3 -m venv .venv
# shellcheck disable=SC1091
. .venv/bin/activate

python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r requirements.txt
# Test/dev tooling, when present.
[ -f requirements-dev.txt ] && python -m pip install --quiet -r requirements-dev.txt

# Persist the venv for the rest of the session.
{
  echo "export VIRTUAL_ENV=\"$CLAUDE_PROJECT_DIR/.venv\""
  echo "export PATH=\"$CLAUDE_PROJECT_DIR/.venv/bin:\$PATH\""
} >> "$CLAUDE_ENV_FILE"
