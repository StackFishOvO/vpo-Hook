#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
exec node --require ./preload.js ./guest.js
