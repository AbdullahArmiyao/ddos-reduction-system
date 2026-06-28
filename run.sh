#!/usr/bin/env bash
# Direct shortcut to the execution script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec sudo bash "$SCRIPT_DIR/scripts/run.sh" "$@"
