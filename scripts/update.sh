#!/usr/bin/env bash
# Update nanobot on the remote RPi and restart the service.
# Usage: bash scripts/update.sh

set -euo pipefail

REMOTE="yavfast@10.0.198.120"
REMOTE_DIR="~/nanobot"
VENV_PIP="~/venv/bin/pip"
SERVICE="nanobot-gateway"

echo "==> Stopping $SERVICE on $REMOTE..."
ssh "$REMOTE" "systemctl --user stop $SERVICE"

echo "==> Installing nanobot (editable) on $REMOTE..."
ssh "$REMOTE" "cd $REMOTE_DIR && $VENV_PIP install -e . --quiet"

echo "==> Starting $SERVICE on $REMOTE..."
ssh "$REMOTE" "systemctl --user start $SERVICE"

echo "==> Status:"
ssh "$REMOTE" "systemctl --user status $SERVICE --no-pager -l"
