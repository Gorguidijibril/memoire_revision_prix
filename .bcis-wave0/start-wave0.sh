#!/usr/bin/env bash
set -euo pipefail
mkdir -p .bcis-wave0/bundle
base64 -d .bcis-wave0/bundle.tar.gz.b64 | tar -xz -C .bcis-wave0/bundle
node .bcis-wave0/runner.mjs
exec node .bcis-wave0/hold.mjs
