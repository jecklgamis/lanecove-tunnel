#!/usr/bin/env bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
"${SCRIPT_DIR}/../lanecove" -c "${SCRIPT_DIR}/../config/peer-1.yaml"
